# mythos-core/api/http/middleware/auth.py
from __future__ import annotations

import asyncio
import base64
import contextvars
import dataclasses
import hmac
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, Union

import httpx
import jwt  # PyJWT
from jwt import PyJWKClient, InvalidTokenError, PyJWTError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

logger = logging.getLogger("mythos.auth")


# ===========================
# Конфигурация и модели
# ===========================

@dataclass(frozen=True)
class AuthSettings:
    # JWT
    issuer: Optional[str] = field(default_factory=lambda: os.getenv("AUTH_OIDC_ISSUER"))
    audience: Optional[str] = field(default_factory=lambda: os.getenv("AUTH_OIDC_AUDIENCE"))
    jwks_url: Optional[str] = field(default_factory=lambda: os.getenv("AUTH_JWKS_URL"))
    jwt_algorithms: Tuple[str, ...] = field(default_factory=lambda: tuple((os.getenv("AUTH_JWT_ALGS") or "RS256,ES256,HS256").split(",")))
    jwt_hs_secret: Optional[str] = field(default_factory=lambda: os.getenv("AUTH_JWT_HS_SECRET"))
    jwt_clock_skew: int = int(os.getenv("AUTH_JWT_CLOCK_SKEW", "60"))  # секунды

    # API-ключи: формат значения переменной AUTH_API_KEYS пример:
    # "key1:role:admin,role:writer;key2:role:reader" или "key_id=abc:key=base64secret:roles=admin|writer"
    api_key_header: str = os.getenv("AUTH_API_KEY_HEADER", "X-API-Key")
    api_key_query: str = os.getenv("AUTH_API_KEY_QUERY", "api_key")
    api_keys_raw: Optional[str] = field(default_factory=lambda: os.getenv("AUTH_API_KEYS"))
    api_key_hash: bool = os.getenv("AUTH_API_KEY_HASHED", "false").lower() == "true"  # если true, сравниваем хэши ключей

    # JWKS кэш
    jwks_cache_ttl: int = int(os.getenv("AUTH_JWKS_CACHE_TTL", "900"))  # 15 минут
    jwks_refresh_jitter: int = int(os.getenv("AUTH_JWKS_REFRESH_JITTER", "30"))  # от заштормливания
    http_timeout_s: float = float(os.getenv("AUTH_HTTP_TIMEOUT", "5.0"))

    # Общие настройки
    enforce_auth: bool = os.getenv("AUTH_ENFORCE", "false").lower() == "true"
    anonymous_allowed_paths: Tuple[str, ...] = field(default_factory=lambda: tuple((os.getenv("AUTH_ANON_PATHS") or "/healthz,/docs,/openapi.json").split(",")))

    # Сопоставление claim -> scopes
    jwt_scope_claims: Tuple[str, ...] = field(default_factory=lambda: tuple((os.getenv("AUTH_JWT_SCOPE_CLAIMS") or "scope,scopes").split(",")))
    role_claims: Tuple[str, ...] = field(default_factory=lambda: tuple((os.getenv("AUTH_JWT_ROLE_CLAIMS") or "roles,role").split(",")))

    # Генерация анонимного пользователя
    allow_anonymous: bool = os.getenv("AUTH_ALLOW_ANON", "true").lower() == "true"


@dataclass
class Principal:
    subject: str
    token_type: str  # "jwt" | "api_key" | "anonymous"
    scopes: Set[str] = field(default_factory=set)
    roles: Set[str] = field(default_factory=set)
    token_id: Optional[str] = None
    claims: Dict[str, Any] = field(default_factory=dict)
    tenant: Optional[str] = None
    auth_time: Optional[int] = None  # unix
    api_key_id: Optional[str] = None

    @property
    def user_id(self) -> str:
        return self.claims.get("sub") or self.subject

    def has_scopes(self, required: Iterable[str]) -> bool:
        req = set(required)
        return req.issubset(self.scopes)

    def has_any_scope(self, required: Iterable[str]) -> bool:
        return bool(set(required).intersection(self.scopes))

    def has_roles(self, required: Iterable[str]) -> bool:
        return set(required).issubset(self.roles)


# Контекст текущего principal
_current_principal: contextvars.ContextVar[Optional[Principal]] = contextvars.ContextVar("current_principal", default=None)


def get_current_principal() -> Optional[Principal]:
    return _current_principal.get()


# ===========================
# JWKS кэш с защитой от штормов
# ===========================

class _JWKSCache:
    def __init__(self, ttl: int, jitter: int) -> None:
        self._ttl = ttl
        self._jitter = jitter
        self._jwks: Optional[Dict[str, Any]] = None
        self._expires_at: float = 0.0
        self._lock = asyncio.Lock()

    def _expired(self) -> bool:
        return time.time() >= self._expires_at

    async def get(self, url: str, timeout: float) -> Dict[str, Any]:
        if self._jwks and not self._expired():
            return self._jwks
        async with self._lock:
            if self._jwks and not self._expired():
                return self._jwks
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()
            # Устанавливаем срок жизни с небольшим джиттером
            jitter = min(self._jitter, max(0, int(self._ttl * 0.2)))
            self._jwks = data
            self._expires_at = time.time() + self._ttl - jitter
            return self._jwks


# ===========================
# Провайдеры проверки токенов
# ===========================

class JWTProvider:
    def __init__(self, settings: AuthSettings) -> None:
        self._s = settings
        self._jwks_cache = _JWKSCache(ttl=settings.jwks_cache_ttl, jitter=settings.jwks_refresh_jitter)

    async def verify(self, token: str) -> Principal:
        options = {
            "verify_signature": True,
            "verify_aud": bool(self._s.audience),
            "verify_iss": bool(self._s.issuer),
            "require": ["exp", "iat"],
        }
        algorithms = tuple(a.strip() for a in self._s.jwt_algorithms if a.strip())
        unverified = jwt.get_unverified_header(token)

        # Верификация по HMAC если задан секрет и алгоритм HS*
        if self._s.jwt_hs_secret and any(a.startswith("HS") for a in algorithms):
            try:
                claims = jwt.decode(
                    token,
                    key=self._s.jwt_hs_secret,
                    algorithms=[alg for alg in algorithms if alg.startswith("HS")],
                    audience=self._s.audience,
                    issuer=self._s.issuer,
                    options=options,
                    leeway=self._s.jwt_clock_skew,
                )
                return self._principal_from_claims(claims, token_type="jwt")
            except InvalidTokenError as e:
                raise AuthError("invalid_token", f"JWT validation failed: {e}")

        # Иначе JWKS
        if not self._s.jwks_url and self._s.issuer:
            # Попытка стандартного пути .well-known (OIDC)
            jwks_url = self._s.issuer.rstrip("/") + "/.well-known/jwks.json"
        else:
            jwks_url = self._s.jwks_url

        if not jwks_url:
            raise AuthError("misconfigured", "JWKS URL or HS secret must be configured")

        jwks = await self._jwks_cache.get(jwks_url, timeout=self._s.http_timeout_s)

        # Поиск ключа по kid
        kid = unverified.get("kid")
        key = self._select_jwk(jwks, kid)
        if key is None:
            raise AuthError("key_not_found", "Matching JWK not found")

        try:
            claims = jwt.decode(
                token,
                key=jwt.algorithms.Algorithm.from_jwk(json.dumps(key)),
                algorithms=[alg for alg in algorithms if not alg.startswith("HS")],
                audience=self._s.audience,
                issuer=self._s.issuer,
                options=options,
                leeway=self._s.jwt_clock_skew,
            )
            return self._principal_from_claims(claims, token_type="jwt")
        except InvalidTokenError as e:
            raise AuthError("invalid_token", f"JWT validation failed: {e}")

    @staticmethod
    def _select_jwk(jwks: Mapping[str, Any], kid: Optional[str]) -> Optional[Dict[str, Any]]:
        keys = jwks.get("keys", [])
        if kid:
            for k in keys:
                if k.get("kid") == kid:
                    return k
        # fallback: если один ключ
        if len(keys) == 1:
            return keys[0]
        return None

    def _principal_from_claims(self, claims: Mapping[str, Any], token_type: str) -> Principal:
        scopes: Set[str] = set()
        roles: Set[str] = set()

        for c in self._s.jwt_scope_claims:
            val = claims.get(c)
            if isinstance(val, str):
                scopes |= set(v for v in re.split(r"[,\s]+", val) if v)
            elif isinstance(val, (list, tuple)):
                scopes |= set(map(str, val))

        for r in self._s.role_claims:
            val = claims.get(r)
            if isinstance(val, str):
                roles |= set(v for v in re.split(r"[,\s]+", val) if v)
            elif isinstance(val, (list, tuple)):
                roles |= set(map(str, val))

        tenant = claims.get("tenant") or claims.get("tid") or claims.get("org")
        jti = claims.get("jti")
        auth_time = claims.get("auth_time") or claims.get("iat")

        return Principal(
            subject=str(claims.get("sub") or ""),
            token_type=token_type,
            scopes=scopes,
            roles=roles,
            token_id=jti,
            claims=dict(claims),
            tenant=tenant,
            auth_time=int(auth_time) if isinstance(auth_time, (int, float)) else None,
        )


class APIKeyProvider:
    def __init__(self, settings: AuthSettings) -> None:
        self._s = settings
        self._keys: Dict[str, Dict[str, Any]] = self._parse_keys(settings.api_keys_raw)

    @staticmethod
    def _parse_keys(raw: Optional[str]) -> Dict[str, Dict[str, Any]]:
        """
        Поддерживаем несколько форматов, разделитель ключей — ';'
        Примеры:
          "writer:MYSECRET;reader:ANOTHER"
          "id=svc1:key=BASE64:roles=admin|writer;id=svc2:key=K2:roles=reader"
        """
        result: Dict[str, Dict[str, Any]] = {}
        if not raw:
            return result
        for chunk in filter(None, [s.strip() for s in raw.split(";")]):
            entry: Dict[str, Any] = {}
            if "=" in chunk and ":" in chunk:
                # key-value формат
                parts = [p.strip() for p in chunk.split(":")]
                for p in parts:
                    if "=" in p:
                        k, v = p.split("=", 1)
                        entry[k.strip()] = v.strip()
                key_id = str(entry.get("id") or entry.get("name") or len(result))
                key = entry.get("key")
                roles = entry.get("roles", "")
                entry["roles"] = set(filter(None, roles.split("|"))) if roles else set()
                entry["key"] = key
                result[key_id] = entry
            else:
                # "name:secret[:role:admin,role:writer]"
                parts = chunk.split(":")
                key_id = parts[0]
                key = parts[1] if len(parts) > 1 else ""
                roles: Set[str] = set()
                if len(parts) > 2:
                    for p in parts[2:]:
                        if p.startswith("role"):
                            _, val = p.split("=", 1) if "=" in p else ("role", p.split("role", 1)[-1])
                            roles |= set(filter(None, re.split(r"[,\|]+", val)))
                result[key_id] = {"id": key_id, "key": key, "roles": roles}
        return result

    def verify(self, presented_key: str) -> Principal:
        if not self._keys:
            raise AuthError("no_apikeys", "API keys not configured")
        for key_id, rec in self._keys.items():
            secret = rec.get("key") or ""
            if not secret:
                continue
            if self._s.api_key_hash:
                # Сравнение sha256
                try:
                    secret_bytes = base64.b16decode(secret.upper())
                except Exception:
                    secret_bytes = secret.encode("utf-8")
                presented_bytes = presented_key.encode("utf-8")
                if hmac.compare_digest(secret_bytes, presented_bytes):
                    return Principal(subject=key_id, token_type="api_key", roles=set(rec.get("roles", set())), api_key_id=key_id)
            else:
                if hmac.compare_digest(secret, presented_key):
                    return Principal(subject=key_id, token_type="api_key", roles=set(rec.get("roles", set())), api_key_id=key_id)
        raise AuthError("invalid_api_key", "API key not recognized")


# ===========================
# Ошибки и ответы
# ===========================

class AuthError(Exception):
    def __init__(self, code: str, message: str, status: int = 401) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def _problem(status: int, code: str, title: str, detail: Optional[str] = None) -> JSONResponse:
    payload = {
        "type": f"https://httpstatuses.com/{status}",
        "title": title,
        "status": status,
        "code": code,
        "detail": detail or title,
    }
    return JSONResponse(payload, status_code=status)


# ===========================
# Проверка скоупов на уровне хэндлеров
# ===========================

def require_scopes(*scopes: str, any_of: bool = False, roles: Optional[Sequence[str]] = None) -> Callable:
    """
    Декоратор для эндпоинтов FastAPI/Starlette.
    Пример:
        @app.get("/v1/data")
        @require_scopes("read:data", roles=["reader","admin"])
        async def handler(...): ...
    """
    req_scopes = set(scopes)
    req_roles = set(roles or [])

    def decorator(fn: Callable) -> Callable:
        setattr(fn, "_required_scopes", req_scopes)
        setattr(fn, "_required_any_scope", any_of)
        setattr(fn, "_required_roles", req_roles)

        @wraps(fn)
        async def wrapper(*args, **kwargs):
            return await fn(*args, **kwargs)

        return wrapper

    return decorator


def _extract_requirements(request: Request) -> Tuple[Set[str], bool, Set[str]]:
    endpoint = request.scope.get("endpoint")
    if not endpoint:
        return set(), False, set()
    req_scopes: Set[str] = getattr(endpoint, "_required_scopes", set())
    any_of: bool = getattr(endpoint, "_required_any_scope", False)
    req_roles: Set[str] = getattr(endpoint, "_required_roles", set())
    return req_scopes, any_of, req_roles


# ===========================
# Middleware
# ===========================

class AuthMiddleware(BaseHTTPMiddleware):
    """
    Встраивание:
        app.add_middleware(
            AuthMiddleware,
            settings=AuthSettings(),
            exempt_paths=[r"^/healthz$", r"^/docs", r"^/openapi.json"],
        )
    """

    def __init__(
        self,
        app: ASGIApp,
        settings: Optional[AuthSettings] = None,
        exempt_paths: Optional[Sequence[str]] = None,
    ) -> None:
        super().__init__(app)
        self._s = settings or AuthSettings()
        self._jwt = JWTProvider(self._s)
        self._apikey = APIKeyProvider(self._s)
        self._exempt_patterns: List[re.Pattern[str]] = [re.compile(p) for p in (exempt_paths or self._s.anonymous_allowed_paths or [])]

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        path = request.url.path
        is_exempt = any(p.search(path) for p in self._exempt_patterns)

        try:
            principal = await self._authenticate(request)
        except AuthError as e:
            logger.debug("auth_error", extra={"code": e.code, "path": path})
            # Если путь исключен и аноним доступен — пропускаем как аноним
            if is_exempt and self._s.allow_anonymous:
                principal = Principal(subject="anonymous", token_type="anonymous", scopes=set(), roles=set())
            else:
                status = e.status if e.status else 401
                return _problem(status, e.code, "Unauthorized", e.message)

        # Сохраняем principal в контекст и state
        token = _current_principal.set(principal)
        request.state.principal = principal

        # Проверка требований эндпоинта
        req_scopes, any_of, req_roles = _extract_requirements(request)
        if req_roles and not principal.roles.issuperset(req_roles):
            _current_principal.reset(token)
            return _problem(403, "forbidden", "Forbidden", "Required roles are missing")
        if req_scopes:
            if any_of:
                if not principal.has_any_scope(req_scopes):
                    _current_principal.reset(token)
                    return _problem(403, "forbidden", "Forbidden", "Required scopes are missing")
            else:
                if not principal.has_scopes(req_scopes):
                    _current_principal.reset(token)
                    return _problem(403, "forbidden", "Forbidden", "Required scopes are missing")

        # Если аутентификации не было и требуется принудительно
        if principal.token_type == "anonymous" and self._s.enforce_auth and not is_exempt:
            _current_principal.reset(token)
            return _problem(401, "unauthenticated", "Unauthorized", "Authentication required")

        try:
            response = await call_next(request)
        finally:
            _current_principal.reset(token)
        return response

    async def _authenticate(self, request: Request) -> Principal:
        # 1) Authorization: Bearer
        auth = request.headers.get("Authorization")
        if auth and auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()
            return await self._jwt.verify(token)

        # 2) API-ключ: заголовок
        key_hdr = request.headers.get(self._s.api_key_header)
        if key_hdr:
            return self._apikey.verify(key_hdr.strip())

        # 3) API-ключ: query
        q = request.query_params.get(self._s.api_key_query)
        if q:
            return self._apikey.verify(q.strip())

        # 4) Аноним
        if self._s.allow_anonymous:
            return Principal(subject="anonymous", token_type="anonymous", scopes=set(), roles=set())

        raise AuthError("no_credentials", "No credentials provided")


# ===========================
# Хелперы для FastAPI
# ===========================

def as_fastapi_dependency(required_scopes: Optional[Sequence[str]] = None, any_of: bool = False, roles: Optional[Sequence[str]] = None):
    """
    Пример:
        get_current = as_fastapi_dependency(required_scopes=["read:quests"], roles=["reader"])
        @app.get("/v1/quests")
        async def list_quets(principal: Principal = Depends(get_current)):
            ...
    """
    req_scopes = set(required_scopes or [])
    req_roles = set(roles or [])

    async def dep(request: Request) -> Principal:
        principal: Optional[Principal] = getattr(request.state, "principal", None)
        if principal is None:
            raise AuthError("unauthenticated", "Missing authentication context")
        if req_roles and not principal.roles.issuperset(req_roles):
            raise AuthError("forbidden", "Required roles are missing", status=403)
        if req_scopes:
            if any_of:
                if not principal.has_any_scope(req_scopes):
                    raise AuthError("forbidden", "Required scopes are missing", status=403)
            else:
                if not principal.has_scopes(req_scopes):
                    raise AuthError("forbidden", "Required scopes are missing", status=403)
        return principal

    return dep
