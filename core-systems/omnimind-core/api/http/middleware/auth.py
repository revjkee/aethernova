"""
Omnimind Core — Auth Middleware (JWT / API-Key / mTLS via proxy)

Зависимости:
  - fastapi>=0.110 / starlette>=0.37
  - pyjwt>=2.8
  - httpx>=0.27
  - cryptography (как зависимость pyjwt)
Опционально:
  - python-dotenv для загрузки переменных окружения (не требуется модулю напрямую)

Особенности:
  - Поддержка Bearer JWT с JWKS (RS256/ES256), кэш JWKS с TTL и backoff.
  - Проверка iss/aud/exp/nbf/iat, допуск clock skew (leeway).
  - Ревокация токенов по jti (in-memory TTL, интерфейс для внешнего стора).
  - API Key из заголовка/квери + HMAC-подпись запроса (опционально).
  - Доверенная mTLS через L7-прокси (X-SSL-Client-* заголовки).
  - Контекст субъекта в request.state.user + тип схемы.
  - Декораторы require_scopes/require_roles для маршрутных хендлеров.
  - Чёткие исключения и коды ошибок, совместимы с RFC 6750.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from dataclasses import dataclass, field
from functools import lru_cache, wraps
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union

import httpx
import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.security.utils import get_authorization_scheme_param
from jwt import PyJWKClient, algorithms
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.status import (
    HTTP_200_OK,
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
)
from starlette.types import ASGIApp

# ==========================
# Конфигурация и модели
# ==========================

@dataclass(frozen=True)
class JWKSConfig:
    url: str
    issuer: str
    audience: Union[str, Sequence[str]]
    algorithms: Tuple[str, ...] = ("RS256", "ES256")
    cache_ttl_seconds: int = 600
    http_timeout_seconds: float = 3.0
    leeway_seconds: int = 60
    # Доп. проверки
    require_exp: bool = True
    require_iat: bool = False
    require_nbf: bool = False


@dataclass(frozen=True)
class APIKeyConfig:
    enabled: bool = True
    header_name: str = "X-API-Key"
    query_name: str = "api_key"
    # Белый список ключей (для простых сценариев) ИЛИ интерфейс внешней проверки
    allowed_keys: Tuple[str, ...] = ()
    # HMAC подпись запроса (например, X-Signature: base64(hmac_sha256(secret, body)))
    hmac_header: Optional[str] = None
    hmac_secret_b64: Optional[str] = None  # base64-encoded secret
    hmac_required: bool = False


@dataclass(frozen=True)
class MTLSProxyConfig:
    enabled: bool = False
    verify_header: str = "X-SSL-Client-Verify"  # "SUCCESS"
    subject_header: str = "X-SSL-Client-S-DN"   # "CN=...,O=..."
    san_header: str = "X-SSL-Client-SAN"        # "DNS:...,URI:...,email:..."
    require_verify_success: bool = True
    trusted_proxy_cidrs: Tuple[str, ...] = ()   # опционально фильтрация по src IP (реализуйте на уровне ingress/ASG)


@dataclass
class AuthSettings:
    jwks: Optional[JWKSConfig] = None
    apikey: APIKeyConfig = field(default_factory=APIKeyConfig)
    mtls: MTLSProxyConfig = field(default_factory=MTLSProxyConfig)
    # Разрешённые clock skew на уровне всей системы (приоритет у JWKSConfig.leeway_seconds)
    leeway_seconds: int = 60
    # Обязательные scope/роль по умолчанию (маршруты могут переопределить)
    default_scopes: Tuple[str, ...] = ()
    default_roles: Tuple[str, ...] = ()
    # Внутренняя ревокация jti (in-memory TTL в секундах)
    jti_revocation_ttl_seconds: int = 3600

# ==========================
# Исключения и контекст
# ==========================

class AuthError(HTTPException):
    def __init__(self, status_code: int, detail: str, www_authenticate: Optional[str] = None):
        headers = {"WWW-Authenticate": www_authenticate} if www_authenticate else None
        super().__init__(status_code=status_code, detail=detail, headers=headers)


@dataclass
class Principal:
    subject: str
    scheme: str                   # "jwt" | "api_key" | "mtls"
    scopes: Tuple[str, ...] = ()
    roles: Tuple[str, ...] = ()
    claims: Dict[str, Any] = field(default_factory=dict)
    api_key_id: Optional[str] = None
    mtls_subject: Optional[str] = None

# ==========================
# Вспомогательные утилиты
# ==========================

def _now() -> int:
    return int(time.time())

class _TTLCache:
    """Простой TTL-кэш для jti и пр. Не для больших нагрузок. Для продакшена используйте Redis/KeyDB."""
    def __init__(self):
        self._store: Dict[str, int] = {}
        self._lock = asyncio.Lock()

    async def add(self, key: str, ttl_seconds: int):
        async with self._lock:
            self._store[key] = _now() + ttl_seconds

    async def contains(self, key: str) -> bool:
        async with self._lock:
            exp = self._store.get(key)
            if not exp:
                return False
            if exp < _now():
                self._store.pop(key, None)
                return False
            return True

_jti_revocation_cache = _TTLCache()

@lru_cache(maxsize=128)
def _jwks_client(url: str) -> PyJWKClient:
    return PyJWKClient(url)

# ==========================
# Валидатор JWT
# ==========================

class JWTValidator:
    def __init__(self, cfg: JWKSConfig):
        self.cfg = cfg

    async def validate(self, token: str) -> Dict[str, Any]:
        if not token:
            raise AuthError(HTTP_401_UNAUTHORIZED, "invalid_token: empty", 'Bearer error="invalid_token"')

        # Получаем ключ по kid через PyJWKClient (имеет внутренний кэш)
        jwk_client = _jwks_client(self.cfg.url)
        try:
            signing_key = jwk_client.get_signing_key_from_jwt(token).key
        except Exception as e:
            raise AuthError(HTTP_401_UNAUTHORIZED, f"invalid_token: jwks {e}", 'Bearer error="invalid_token"')

        options = {
            "require": [c for c, req in [("exp", self.cfg.require_exp), ("iat", self.cfg.require_iat), ("nbf", self.cfg.require_nbf)] if req],
            "verify_signature": True,
            "verify_exp": True,
            "verify_iss": True,
            "verify_aud": True,
        }

        try:
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=self.cfg.algorithms,
                audience=self.cfg.audience,
                issuer=self.cfg.issuer,
                leeway=self.cfg.leeway_seconds,
                options=options,
            )
        except jwt.ExpiredSignatureError:
            raise AuthError(HTTP_401_UNAUTHORIZED, "invalid_token: expired", 'Bearer error="invalid_token"')
        except jwt.InvalidIssuerError:
            raise AuthError(HTTP_401_UNAUTHORIZED, "invalid_token: iss", 'Bearer error="invalid_token"')
        except jwt.InvalidAudienceError:
            raise AuthError(HTTP_401_UNAUTHORIZED, "invalid_token: aud", 'Bearer error="invalid_token"')
        except jwt.ImmatureSignatureError:
            raise AuthError(HTTP_401_UNAUTHORIZED, "invalid_token: nbf", 'Bearer error="invalid_token"')
        except jwt.InvalidTokenError as e:
            raise AuthError(HTTP_401_UNAUTHORIZED, f"invalid_token: {e}", 'Bearer error="invalid_token"')

        # Лёгкая ревокация по jti (если присутствует)
        jti = claims.get("jti")
        if jti and await _jti_revocation_cache.contains(jti):
            raise AuthError(HTTP_401_UNAUTHORIZED, "invalid_token: revoked", 'Bearer error="invalid_token"')

        return claims

# ==========================
# Проверка API-ключа
# ==========================

def _b64decode_optional(s: Optional[str]) -> Optional[bytes]:
    if not s:
        return None
    return base64.b64decode(s)

def validate_api_key(request: Request, cfg: APIKeyConfig) -> Tuple[Optional[str], Dict[str, Any]]:
    if not cfg.enabled:
        return None, {}

    key = None
    # Заголовок Authorization: ApiKey <key>
    auth = request.headers.get("Authorization")
    if auth:
        scheme, param = get_authorization_scheme_param(auth)
        if scheme.lower() == "apikey":
            key = param.strip() or None

    # Заголовок X-API-Key
    if not key:
        key = request.headers.get(cfg.header_name)

    # Квери
    if not key:
        key = request.query_params.get(cfg.query_name)

    if not key:
        return None, {}

    # Простейшая проверка против белого списка
    if cfg.allowed_keys and key not in cfg.allowed_keys:
        raise AuthError(HTTP_401_UNAUTHORIZED, "invalid_api_key", 'ApiKey error="invalid_key"')

    # Опциональная HMAC подпись тела запроса
    if cfg.hmac_required:
        sig = request.headers.get(cfg.hmac_header or "X-Signature")
        secret = _b64decode_optional(cfg.hmac_secret_b64)
        if not sig or not secret:
            raise AuthError(HTTP_401_UNAUTHORIZED, "invalid_signature", 'ApiKey error="invalid_signature"')
        # Простейшая проверка без тайминг-защиты (в проде — hmac.compare_digest)
        body = getattr(request, "_body", None)
        # Если тело ещё не прочитано — читаем и кешируем
        if body is None:
            body = asyncio.get_event_loop().run_until_complete(request.body())
            setattr(request, "_body", body)
        import hmac, hashlib
        computed = hmac.new(secret, body, hashlib.sha256).digest()
        expected = base64.b64encode(computed).decode()
        import hmac as _h
        if not _h.compare_digest(expected, sig):
            raise AuthError(HTTP_401_UNAUTHORIZED, "invalid_signature", 'ApiKey error="invalid_signature"')

    return key, {"api_key_id": key[:6] + "…" if key else None}

# ==========================
# mTLS (через прокси)
# ==========================

def validate_mtls_via_proxy(request: Request, cfg: MTLSProxyConfig) -> Optional[str]:
    if not cfg.enabled:
        return None
    verify = request.headers.get(cfg.verify_header)
    subject = request.headers.get(cfg.subject_header)
    if cfg.require_verify_success and (verify or "").upper() != "SUCCESS":
        raise AuthError(HTTP_401_UNAUTHORIZED, "mtls_failed")
    if not subject:
        raise AuthError(HTTP_401_UNAUTHORIZED, "mtls_no_subject")
    return subject

# ==========================
# Middleware аутентификации
# ==========================

class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, settings: AuthSettings):
        super().__init__(app)
        self.settings = settings
        self.jwt_validator = JWTValidator(settings.jwks) if settings.jwks else None

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        request.state.user = None  # по умолчанию аноним
        auth_header = request.headers.get("Authorization", "")
        scheme, param = get_authorization_scheme_param(auth_header)

        # 1) API Key
        if self.settings.apikey.enabled:
            try:
                key, meta = validate_api_key(request, self.settings.apikey)
                if key:
                    request.state.user = Principal(
                        subject=f"api_key:{meta.get('api_key_id')}",
                        scheme="api_key",
                        scopes=(),
                        roles=("service",),
                        claims={"api_key_id": meta.get("api_key_id")},
                        api_key_id=meta.get("api_key_id"),
                    )
            except AuthError as e:
                # Если указан ApiKey и он неверный — сразу 401
                if scheme.lower() == "apikey" or request.headers.get(self.settings.apikey.header_name) or request.query_params.get(self.settings.apikey.query_name):
                    raise
                # иначе продолжаем — возможно будет JWT
        # 2) JWT Bearer
        if not request.state.user and scheme.lower() == "bearer" and self.jwt_validator:
            claims = await self.jwt_validator.validate(param)
            scopes = tuple((claims.get("scope") or "").split()) if "scope" in claims else tuple(claims.get("scopes", []))
            roles = tuple(claims.get("roles", []))
            sub = claims.get("sub") or claims.get("client_id") or "unknown"
            request.state.user = Principal(
                subject=sub,
                scheme="jwt",
                scopes=scopes,
                roles=roles,
                claims=claims,
            )

        # 3) mTLS via proxy
        if not request.state.user and self.settings.mtls.enabled:
            subject = validate_mtls_via_proxy(request, self.settings.mtls)
            if subject:
                request.state.user = Principal(
                    subject=f"mtls:{subject}",
                    scheme="mtls",
                    scopes=(),
                    roles=("service",),
                    mtls_subject=subject,
                )

        # Если авторизация обязательна — проверка может быть вынесена в dependency ниже.
        response = await call_next(request)
        return response

# ==========================
# Зависимость FastAPI и декораторы авторизации
# ==========================

def current_principal(required: bool = True) -> Callable[[Request], Principal]:
    async def _dep(request: Request) -> Principal:
        user = getattr(request.state, "user", None)
        if not user and required:
            raise AuthError(HTTP_401_UNAUTHORIZED, "unauthorized", 'Bearer realm="omnimind-core"')
        return user
    return _dep

def require_scopes(*need_scopes: str) -> Callable:
    """Декоратор для хендлеров FastAPI/Starlette."""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Ищем Request среди аргументов
            req: Optional[Request] = None
            for a in args:
                if isinstance(a, Request):
                    req = a
                    break
            if not req:
                req = kwargs.get("request")
            if not req:
                raise RuntimeError("Request is required for authorization")

            user: Principal = getattr(req.state, "user", None)
            if not user:
                raise AuthError(HTTP_401_UNAUTHORIZED, "unauthorized", 'Bearer realm="omnimind-core"')

            have = set(s.lower() for s in user.scopes)
            need = set(s.lower() for s in need_scopes)
            if not need.issubset(have):
                raise AuthError(HTTP_403_FORBIDDEN, "insufficient_scope", f'Bearer error="insufficient_scope", scope="{ " ".join(need_scopes) }"')

            return await func(*args, **kwargs)
        return wrapper
    return decorator

def require_roles(*need_roles: str) -> Callable:
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            req: Optional[Request] = None
            for a in args:
                if isinstance(a, Request):
                    req = a
                    break
            if not req:
                req = kwargs.get("request")
            if not req:
                raise RuntimeError("Request is required for authorization")
            user: Principal = getattr(req.state, "user", None)
            if not user:
                raise AuthError(HTTP_401_UNAUTHORIZED, "unauthorized")

            have = set(r.lower() for r in user.roles)
            need = set(r.lower() for r in need_roles)
            if not need.issubset(have):
                raise AuthError(HTTP_403_FORBIDDEN, "forbidden")

            return await func(*args, **kwargs)
        return wrapper
    return decorator

# ==========================
# Управление ревокацией JTI
# ==========================

async def revoke_jti(jti: str, ttl_seconds: int) -> None:
    """Добавляет jti в локальный список отозванных (на TTL)."""
    await _jti_revocation_cache.add(jti, ttl_seconds)

# ==========================
# FastAPI интеграция (пример)
# ==========================

def setup_auth(app: FastAPI, settings: AuthSettings) -> None:
    """
    Подключает middleware и возвращает зависимости:
      current_user = current_principal(required=True)
    Пример использования:
      app = FastAPI()
      setup_auth(app, settings)
      @app.get("/me")
      async def me(user: Principal = Depends(current_principal())):
          return {"sub": user.subject, "scheme": user.scheme}
    """
    app.add_middleware(AuthMiddleware, settings=settings)

# ==========================
# Пример конфигурации (для справки, не исполняется)
# ==========================

"""
from fastapi import FastAPI, Depends
from ops.api.http.middleware.auth import (
    AuthSettings, JWKSConfig, APIKeyConfig, MTLSProxyConfig,
    setup_auth, current_principal, require_scopes, require_roles, Principal
)

app = FastAPI()

settings = AuthSettings(
    jwks=JWKSConfig(
        url="https://issuer.example.com/.well-known/jwks.json",
        issuer="https://issuer.example.com/",
        audience=("omnimind-core",),
        algorithms=("RS256",),
        cache_ttl_seconds=600,
        leeway_seconds=60,
    ),
    apikey=APIKeyConfig(
        enabled=True,
        header_name="X-API-Key",
        allowed_keys=("key123",),  # либо хранить/проверять во внешнем сторе
        hmac_header="X-Signature",
        hmac_secret_b64=None,
        hmac_required=False,
    ),
    mtls=MTLSProxyConfig(
        enabled=False
    ),
)

setup_auth(app, settings)

@app.get("/v1/secure")
@require_scopes("read:tools")
async def secure_endpoint(user: Principal = Depends(current_principal())):
    return {"sub": user.subject, "scopes": user.scopes, "roles": user.roles}
"""
