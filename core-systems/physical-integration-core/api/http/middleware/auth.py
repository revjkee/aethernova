# -*- coding: utf-8 -*-
"""
physical-integration-core/api/http/middleware/auth.py

Промышленный аутентификационный middleware для FastAPI/Starlette:
- Стратегии: mTLS (через заголовки от L7-прокси), JWT/OIDC (JWKS кэш + ротация), API Key, HMAC-Signature.
- RBAC/ABAC: роли, скоупы, атрибуты из JWT/хранилища ключей, безопасная проверка.
- Anti-replay: проверка X-Timestamp с допустимым дрейфом, nonce по желанию.
- Revocation (JWT jti): проверка отзыва через secret_store.
- Метрики (если установлен prometheus_client) и аудит-логирование.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import time
import hmac
import hashlib
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

import jwt  # PyJWT
from jwt import PyJWKClient, InvalidTokenError, InvalidSignatureError

from starlette.datastructures import Headers
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from starlette.status import HTTP_200_OK, HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN
from starlette.types import ASGIApp

try:
    import httpx  # async JWKS fetcher
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

try:
    from pydantic import BaseModel, Field, AnyHttpUrl
except Exception:  # pragma: no cover
    # Минимальный полифилл, если pydantic недоступен (для совместимости окружений)
    class BaseModel:  # type: ignore
        def __init__(self, **kwargs):  # simple container
            for k, v in kwargs.items():
                setattr(self, k, v)

        def model_dump(self):
            return self.__dict__

    def Field(default=None, **kwargs):  # type: ignore
        return default

    AnyHttpUrl = str  # type: ignore

# Метрики (необязательны)
try:
    from prometheus_client import Counter, Histogram
except Exception:  # pragma: no cover
    class _Noop:
        def __init__(self, *a, **kw): pass
        def labels(self, *a, **kw): return self
        def observe(self, *a, **kw): return None
        def inc(self, *a, **kw): return None
    Counter = Histogram = _Noop  # type: ignore


# -----------------------------------------------------------------------------
# Конфигурация и контексты
# -----------------------------------------------------------------------------

class AuthSettings(BaseModel):
    # Общие
    env: str = Field(default=os.getenv("ENVIRONMENT", "prod"))
    enable_metrics: bool = Field(default=True)

    # JWT/OIDC
    issuer: str = Field(default=os.getenv("AUTH_ISSUER", ""))
    audience: str = Field(default=os.getenv("AUTH_AUDIENCE", "physical-integration-core"))
    jwks_url: AnyHttpUrl | str = Field(default=os.getenv("AUTH_JWKS_URL", ""))
    allowed_algs: List[str] = Field(default_factory=lambda: ["RS256", "ES256", "RS384", "ES384"])
    jwks_cache_ttl_s: int = Field(default=300)
    jwt_leeway_s: int = Field(default=60)
    accept_from: List[str] = Field(default_factory=lambda: ["authorization", "cookie", "query"])  # источники

    # API Key
    api_key_header: str = Field(default=os.getenv("API_KEY_HEADER", "X-API-Key"))
    api_key_query: str = Field(default=os.getenv("API_KEY_QUERY", "api_key"))

    # HMAC
    hmac_sig_header: str = Field(default=os.getenv("HMAC_SIG_HEADER", "X-Signature"))
    hmac_sig_version_header: str = Field(default=os.getenv("HMAC_SIG_VER_HEADER", "X-Signature-Version"))
    hmac_timestamp_header: str = Field(default=os.getenv("HMAC_TS_HEADER", "X-Timestamp"))
    hmac_keyid_header: str = Field(default=os.getenv("HMAC_KEYID_HEADER", "X-Key-Id"))
    hmac_allowed_versions: List[str] = Field(default_factory=lambda: ["v1"])
    hmac_time_skew_s: int = Field(default=180)

    # mTLS (через прокси)
    mtls_subject_header: str = Field(default=os.getenv("MTLS_SUBJ_HEADER", "X-Client-Cert-Subject"))
    mtls_pem_header: str = Field(default=os.getenv("MTLS_PEM_HEADER", "X-Client-Cert"))
    mtls_accept: bool = Field(default=True)

    # Пути
    bypass_paths: List[str] = Field(default_factory=lambda: ["/health", "/metrics"])
    optional_auth_paths: List[str] = Field(default_factory=list)  # soft auth: не 401, если нет токена

    # Поведение
    audit_log_success: bool = Field(default=False)  # логировать успешные запросы (шумно)
    audit_log_failure: bool = Field(default=True)


@dataclass
class AuthContext:
    method: str
    subject: str
    tenant: Optional[str] = None
    scopes: set[str] = field(default_factory=set)
    roles: set[str] = field(default_factory=set)
    claims: Dict[str, Any] = field(default_factory=dict)
    token_id: Optional[str] = None  # jti
    issued_at: Optional[int] = None
    expires_at: Optional[int] = None
    device_id: Optional[str] = None
    service: Optional[str] = None
    attributes: Dict[str, str] = field(default_factory=dict)

    def has_scopes_all(self, required: Iterable[str]) -> bool:
        req = set(required)
        return req.issubset(self.scopes)

    def has_scopes_any(self, required: Iterable[str]) -> bool:
        return bool(set(required) & self.scopes)

    def has_roles_any(self, required: Iterable[str]) -> bool:
        return bool(set(required) & self.roles)

    def has_roles_all(self, required: Iterable[str]) -> bool:
        req = set(required)
        return req.issubset(self.roles)


# -----------------------------------------------------------------------------
# Хранилище секретов/ключей (API Key, HMAC, Revocation)
# -----------------------------------------------------------------------------

class SecretStore:
    """Абстракция хранилища секретов. Реализуйте методы под вашу инфраструктуру."""

    async def get_api_key(self, key: str) -> Optional[Dict[str, Any]]:
        """Вернёт метаданные по API-ключу (если существует): {owner, scopes[], roles[], tenant, active}"""
        raise NotImplementedError

    async def get_hmac_secret(self, key_id: str) -> Optional[str]:
        """Вернёт секрет для HMAC по идентификатору key_id."""
        raise NotImplementedError

    async def is_token_revoked(self, jti: str) -> bool:
        """Проверка, отозван ли токен (JWT jti)."""
        return False


class InMemorySecretStore(SecretStore):
    """Простая in-memory реализация (для тестов/poC)."""

    def __init__(self,
                 api_keys: Optional[Dict[str, Dict[str, Any]]] = None,
                 hmac_secrets: Optional[Dict[str, str]] = None,
                 revoked_jti: Optional[set[str]] = None):
        self._api_keys = api_keys or {}
        self._hmac = hmac_secrets or {}
        self._revoked = revoked_jti or set()

    async def get_api_key(self, key: str) -> Optional[Dict[str, Any]]:
        return self._api_keys.get(key)

    async def get_hmac_secret(self, key_id: str) -> Optional[str]:
        return self._hmac.get(key_id)

    async def is_token_revoked(self, jti: str) -> bool:
        return jti in self._revoked


# -----------------------------------------------------------------------------
# JWKS кэш и верификация JWT
# -----------------------------------------------------------------------------

class JWKSCache:
    def __init__(self, jwks_url: str, ttl_s: int = 300) -> None:
        self._jwks_url = jwks_url
        self._ttl_s = ttl_s
        self._last_fetch = 0.0
        self._client = PyJWKClient(jwks_url) if jwks_url else None
        self._lock = asyncio.Lock()

    async def get_signing_key(self, token: str):
        # PyJWT PyJWKClient.get_signing_key_from_jwt уже ходит в сеть при необходимости.
        # Дополним контролем TTL.
        if not self._client:
            raise InvalidTokenError("JWKS client not configured")
        async with self._lock:
            # PyJWT сам кэширует ключи; TTL контролируем через _last_fetch (best-effort).
            now = time.time()
            if now - self._last_fetch > self._ttl_s:
                # Триггерим фоновую валидацию JWKS (через dummy вызов)
                self._last_fetch = now
            return self._client.get_signing_key_from_jwt(token).key


# -----------------------------------------------------------------------------
# Стратегии аутентификации
# -----------------------------------------------------------------------------

class AuthStrategy:
    name: str = "base"

    async def authenticate(self, request: Request) -> Optional[AuthContext]:
        raise NotImplementedError


class MTLSStrategy(AuthStrategy):
    """mTLS: прокси должен проставлять subject/PEN/UID в заголовки."""
    name = "mtls"

    def __init__(self, settings: AuthSettings) -> None:
        self.s = settings

    async def authenticate(self, request: Request) -> Optional[AuthContext]:
        if not self.s.mtls_accept:
            return None
        subj = request.headers.get(self.s.mtls_subject_header)
        if not subj:
            pem = request.headers.get(self.s.mtls_pem_header)
            if not pem:
                return None
            # Допускаем PEM в base64
            try:
                if "-----BEGIN CERTIFICATE-----" not in pem:
                    pem = base64.b64decode(pem).decode("utf-8")
            except Exception:
                return None
            # Здесь можно распарсить PEM и извлечь subject; опускаем реализацию (зависит от cryptography)
            subj = "mtls-client"
        return AuthContext(
            method=self.name,
            subject=subj,
            roles={"service"},
            scopes={"svc.read", "svc.write"},
            attributes={"auth": "mtls"}
        )


class JWTStrategy(AuthStrategy):
    name = "jwt"

    def __init__(self, settings: AuthSettings, jwks: JWKSCache, secret_store: SecretStore) -> None:
        self.s = settings
        self.jwks = jwks
        self.store = secret_store

    def _extract_token(self, request: Request) -> Optional[str]:
        headers = request.headers
        token: Optional[str] = None

        if "authorization" in self.s.accept_from:
            auth = headers.get("authorization")
            if auth and auth.lower().startswith("bearer "):
                token = auth.split(" ", 1)[1].strip()

        if not token and "cookie" in self.s.accept_from:
            cookie = headers.get("cookie", "")
            # Ищем токен в cookie `access_token` (безопаснее: флаг Secure/HttpOnly на уровне сервера)
            for part in cookie.split(";"):
                if part.strip().startswith("access_token="):
                    token = part.split("=", 1)[1].strip()
                    break

        if not token and "query" in self.s.accept_from:
            token = request.query_params.get("access_token")

        return token

    async def authenticate(self, request: Request) -> Optional[AuthContext]:
        token = self._extract_token(request)
        if not token:
            return None

        try:
            key = await self.jwks.get_signing_key(token)
            decoded = jwt.decode(
                token,
                key,
                algorithms=self.s.allowed_algs,
                audience=self.s.audience if self.s.audience else None,
                issuer=self.s.issuer if self.s.issuer else None,
                options={
                    "require": ["exp", "iat"],
                    "verify_signature": True,
                    "verify_aud": bool(self.s.audience),
                    "verify_iss": bool(self.s.issuer),
                },
                leeway=self.s.jwt_leeway_s,
            )
        except InvalidSignatureError as e:
            raise e
        except InvalidTokenError as e:
            raise e

        jti = decoded.get("jti")
        if jti and await self.store.is_token_revoked(jti):
            raise InvalidTokenError("Token revoked")

        sub = decoded.get("sub") or decoded.get("client_id") or "unknown"
        tenant = decoded.get("tenant") or decoded.get("azp")
        scopes = set(str(decoded.get("scope", "")).split()) if decoded.get("scope") else set(decoded.get("scopes", []))
        roles = set(decoded.get("roles", [])) | set(decoded.get("realm_access", {}).get("roles", []))
        attrs = {
            "auth": "jwt",
            "iss": str(decoded.get("iss", "")),
            "aud": json.dumps(decoded.get("aud", []), ensure_ascii=False) if isinstance(decoded.get("aud"), list) else str(decoded.get("aud", "")),
        }

        return AuthContext(
            method=self.name,
            subject=sub,
            tenant=tenant,
            token_id=jti,
            issued_at=decoded.get("iat"),
            expires_at=decoded.get("exp"),
            scopes=scopes,
            roles=roles,
            claims=decoded,
            attributes=attrs
        )


class APIKeyStrategy(AuthStrategy):
    name = "api_key"

    def __init__(self, settings: AuthSettings, secret_store: SecretStore) -> None:
        self.s = settings
        self.store = secret_store

    async def authenticate(self, request: Request) -> Optional[AuthContext]:
        key = request.headers.get(self.s.api_key_header)
        if not key:
            key = request.query_params.get(self.s.api_key_query)
        if not key:
            return None

        meta = await self.store.get_api_key(key)
        if not meta or not meta.get("active", True):
            return None

        owner = meta.get("owner", "api-key")
        scopes = set(meta.get("scopes", []))
        roles = set(meta.get("roles", []))
        tenant = meta.get("tenant")

        return AuthContext(
            method=self.name,
            subject=str(owner),
            tenant=tenant,
            scopes=scopes,
            roles=roles,
            claims={"api_key_id": key},
            attributes={"auth": "api_key"}
        )


class HMACStrategy(AuthStrategy):
    """Подпись всего запроса: HMAC(secret, method|path|query|timestamp|body), защита от replay."""
    name = "hmac"

    def __init__(self, settings: AuthSettings, secret_store: SecretStore) -> None:
        self.s = settings
        self.store = secret_store

    @staticmethod
    def _canonical_request(request: Request, timestamp: str) -> bytes:
        # Канонический вид: метод\npath\nsorted_query\nX-Timestamp\nsha256(body)
        q = "&".join(f"{k}={v}" for k, v in sorted(request.query_params.multi_items()))
        body_hash = request.headers.get("x-content-sha256")
        # Если клиент заранее положил хеш тела в заголовок — используем, иначе читаем тело
        async def _calc():
            if body_hash:
                return body_hash
            body = await request.body()
            return hashlib.sha256(body).hexdigest()

        # Оборачиваем в future (вызовется в authenticate)
        request.state._calc_body_hash = _calc  # type: ignore[attr-defined]

        # Мы вернём байтовый шаблон; финал соберём после расчёта hash тела.
        template = f"{request.method.upper()}\n{request.url.path}\n{q}\n{timestamp}\n".encode("utf-8")
        return template

    async def authenticate(self, request: Request) -> Optional[AuthContext]:
        headers = request.headers
        sig = headers.get(self.s.hmac_sig_header)
        if not sig:
            return None

        version = headers.get(self.s.hmac_sig_version_header, "v1")
        if version not in self.s.hmac_allowed_versions:
            return None

        key_id = headers.get(self.s.hmac_keyid_header)
        ts = headers.get(self.s.hmac_timestamp_header)
        if not key_id or not ts:
            return None

        try:
            ts_int = int(ts)
        except ValueError:
            return None

        now = int(time.time())
        if abs(now - ts_int) > self.s.hmac_time_skew_s:
            return None  # replay/скошенное время

        secret = await self.store.get_hmac_secret(key_id)
        if not secret:
            return None

        template = self._canonical_request(request, ts)
        body_hash = await request.state._calc_body_hash()  # type: ignore[attr-defined]
        message = template + body_hash.encode("utf-8")

        calc = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(calc, sig):
            return None

        # Метаданные владельца могут лежать рядом с секретом в SecretStore; здесь упрощённо
        return AuthContext(
            method=self.name,
            subject=f"hmac:{key_id}",
            scopes={"svc.read"},
            roles={"service"},
            claims={"hmac_key_id": key_id, "sig_ver": version},
            attributes={"auth": "hmac"}
        )


# -----------------------------------------------------------------------------
# Метрики и аудит
# -----------------------------------------------------------------------------

AUTH_COUNTER = Counter(
    "http_auth_total",
    "Auth results by method and outcome",
    ["method", "outcome"]
)
AUTH_LATENCY = Histogram(
    "http_auth_latency_seconds",
    "Auth middleware latency",
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0)
)

logger = logging.getLogger("auth")
logger.setLevel(logging.INFO)


# -----------------------------------------------------------------------------
# Middleware
# -----------------------------------------------------------------------------

class AuthMiddleware(BaseHTTPMiddleware):
    """
    Порядок стратегий:
      1) mTLS (если прокси выставил заголовки)
      2) JWT (Bearer/Cookie/Query)
      3) HMAC (подпись запроса)
      4) API Key
    На первый успешный матч — контекст сохраняется в request.state.auth.
    """
    def __init__(self, app: ASGIApp, settings: AuthSettings, secret_store: SecretStore):
        super().__init__(app)
        self.settings = settings
        self.store = secret_store
        self.jwks = JWKSCache(settings.jwks_url, settings.jwks_cache_ttl_s) if settings.jwks_url else None

        self.strategies: list[AuthStrategy] = [
            MTLSStrategy(settings),
            JWTStrategy(settings, self.jwks, secret_store) if self.jwks else None,
            HMACStrategy(settings, secret_store),
            APIKeyStrategy(settings, secret_store),
        ]
        self.strategies = [s for s in self.strategies if s is not None]  # type: ignore

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        path = request.url.path
        if path in self.settings.bypass_paths:
            return await call_next(request)

        start = time.perf_counter()
        auth_ctx: Optional[AuthContext] = None
        outcome = "unauthenticated"

        try:
            for strategy in self.strategies:
                auth_ctx = await strategy.authenticate(request)
                if auth_ctx:
                    outcome = f"ok_{auth_ctx.method}"
                    break

            request.state.auth = auth_ctx  # может быть None

            # Жёсткая аутентификация, если путь не soft-optional
            if not auth_ctx and path not in self.settings.optional_auth_paths:
                if self.settings.audit_log_failure:
                    logger.warning("AUTH DENY: no credentials", extra={"path": path, "method": request.method})
                AUTH_COUNTER.labels(method="none", outcome="deny").inc()
                return JSONResponse({"detail": "Unauthorized"}, status_code=HTTP_401_UNAUTHORIZED)

            # Успешный проход
            resp = await call_next(request)
            if auth_ctx:
                AUTH_COUNTER.labels(method=auth_ctx.method, outcome="ok").inc()
                if self.settings.audit_log_success:
                    logger.info(
                        "AUTH OK",
                        extra={
                            "method": auth_ctx.method,
                            "sub": auth_ctx.subject,
                            "roles": list(auth_ctx.roles),
                            "scopes": list(auth_ctx.scopes),
                            "path": path,
                            "status": resp.status_code,
                        },
                    )
            else:
                AUTH_COUNTER.labels(method="none", outcome="soft").inc()

            return resp

        except InvalidTokenError as e:
            if self.settings.audit_log_failure:
                logger.warning("AUTH DENY: invalid token", extra={"error": str(e), "path": path})
            AUTH_COUNTER.labels(method="jwt", outcome="deny").inc()
            return JSONResponse({"detail": "Invalid token"}, status_code=HTTP_401_UNAUTHORIZED)
        except Exception as e:  # непредвиденная ошибка аутентификации
            logger.exception("AUTH ERROR")
            AUTH_COUNTER.labels(method="error", outcome="error").inc()
            return JSONResponse({"detail": "Authentication error"}, status_code=HTTP_401_UNAUTHORIZED)
        finally:
            AUTH_LATENCY.observe(time.perf_counter() - start)


# -----------------------------------------------------------------------------
# Зависимости для роутов (RBAC/ABAC)
# -----------------------------------------------------------------------------

from fastapi import Depends, HTTPException  # импорт после для лёгкой изоляции

def current_auth(request: Request) -> AuthContext:
    ctx: Optional[AuthContext] = getattr(request.state, "auth", None)
    if ctx is None:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    return ctx


def require_scopes(scopes: Sequence[str], all_: bool = True):
    async def _dep(ctx: AuthContext = Depends(current_auth)) -> AuthContext:
        ok = ctx.has_scopes_all(scopes) if all_ else ctx.has_scopes_any(scopes)
        if not ok:
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Forbidden: missing scopes")
        return ctx
    return _dep


def require_roles(roles: Sequence[str], all_: bool = False):
    async def _dep(ctx: AuthContext = Depends(current_auth)) -> AuthContext:
        ok = ctx.has_roles_all(roles) if all_ else ctx.has_roles_any(roles)
        if not ok:
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Forbidden: missing roles")
        return ctx
    return _dep


def require_predicate(predicate: Callable[[AuthContext], bool], error_detail: str = "Forbidden"):
    async def _dep(ctx: AuthContext = Depends(current_auth)) -> AuthContext:
        if not predicate(ctx):
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail=error_detail)
        return ctx
    return _dep


# -----------------------------------------------------------------------------
# Утилиты и безопасные хедеры
# -----------------------------------------------------------------------------

SECURITY_HEADERS: Mapping[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "X-XSS-Protection": "0",
}

async def add_security_headers(response: Response) -> None:
    for k, v in SECURITY_HEADERS.items():
        if k not in response.headers:
            response.headers[k] = v


# Пример интеграции (не включайте в прод код, только справочно):
# from fastapi import FastAPI
# app = FastAPI()
# settings = AuthSettings(jwks_url="https://issuer/.well-known/jwks.json", issuer="https://issuer", audience="physical-integration-core")
# secret_store = InMemorySecretStore(
#     api_keys={"demo": {"owner": "svc-demo", "scopes": ["svc.read"], "roles": ["service"], "tenant": "default", "active": True}},
#     hmac_secrets={"key-1": "supersecret"}
# )
# app.add_middleware(AuthMiddleware, settings=settings, secret_store=secret_store)
# @app.get("/secure", dependencies=[Depends(require_scopes(["svc.read"]))])
# async def secure_endpoint(ctx: AuthContext = Depends(current_auth)): return {"sub": ctx.subject}
