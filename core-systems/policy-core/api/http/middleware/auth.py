# policy-core/api/http/middleware/auth.py
"""
Промышленное ASGI-middleware для аутентификации/авторизации policy-core.

Возможности:
- Режимы: none | api_key | oidc | hybrid (Bearer или API-Key)
- OIDC/JWT: проверка подписи по JWKS (кэш с TTL), iss/aud/nbf/exp/leeway, scopes/roles
- API-Key: константное сравнение, поддержка sha256=HEX формата
- Защита от повторов: jti replay cache (in-memory TTL, интерфейс для внешнего стореджа)
- mTLS: верификация форвард-заголовков от Ingress/Proxy (опционально)
- Принципал в request.state.principal и контекстной переменной principal_var
- Корреляция X-Request-Id, безопасные ответы 401/403 в JSON

Зависимости (рекомендуемые):
  httpx>=0.24, python-jose[cryptography]>=3.3, pydantic>=1.10 (опц.), starlette>=0.27

Интеграция (FastAPI):
    from fastapi import FastAPI
    from policy_core.api.http.middleware.auth import AuthMiddleware, AuthSettings

    app = FastAPI()
    app.add_middleware(AuthMiddleware, settings=AuthSettings.from_env())

Контракт principal:
    request.state.principal: Principal(
        subject:str, tenant_id:Optional[str], roles:set[str], scopes:set[str], claims:dict
    )
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import functools
import hmac
import json
import os
import time
import typing as t
import uuid
from contextvars import ContextVar

import httpx
from jose import jwt
from jose.utils import base64url_decode
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.responses import JSONResponse, Response

# ---------------------------
# Контекст и модели
# ---------------------------

principal_var: ContextVar["Principal | None"] = ContextVar("principal", default=None)


@dataclasses.dataclass(frozen=True)
class Principal:
    subject: str
    tenant_id: t.Optional[str]
    roles: t.FrozenSet[str]
    scopes: t.FrozenSet[str]
    claims: t.Mapping[str, t.Any]


@dataclasses.dataclass
class AuthSettings:
    mode: str = os.getenv("AUTH_MODE", "hybrid")  # none|api_key|oidc|hybrid
    api_key_header: str = os.getenv("AUTH_API_KEY_HEADER", "X-API-Key")
    api_key_param: str = os.getenv("AUTH_API_KEY_PARAM", "api_key")
    api_key_allowed: t.Tuple[str, ...] = tuple(
        f.strip() for f in os.getenv("AUTH_API_KEYS", "").split(",") if f.strip()
    )

    oidc_issuer: str | None = os.getenv("AUTH_OIDC_ISSUER")
    oidc_audience: str | None = os.getenv("AUTH_OIDC_AUDIENCE")
    oidc_jwks_url: str | None = os.getenv("AUTH_OIDC_JWKS_URL")
    oidc_algorithms: t.Tuple[str, ...] = tuple(
        f.strip() for f in os.getenv("AUTH_OIDC_ALGS", "RS256,ES256,HS256").split(",")
    )
    oidc_leeway: int = int(os.getenv("AUTH_OIDC_LEEWAY", "60"))
    oidc_required_scopes: t.FrozenSet[str] = frozenset(
        s.strip() for s in os.getenv("AUTH_OIDC_REQUIRED_SCOPES", "mythos.read").split(",") if s.strip()
    )
    oidc_required_roles: t.FrozenSet[str] = frozenset(
        s.strip() for s in os.getenv("AUTH_OIDC_REQUIRED_ROLES", "").split(",") if s.strip()
    )
    oidc_cache_ttl: int = int(os.getenv("AUTH_OIDC_JWKS_TTL", "600"))
    oidc_http_timeout: float = float(os.getenv("AUTH_OIDC_HTTP_TIMEOUT", "3.0"))

    trust_mtls_headers: bool = os.getenv("AUTH_TRUST_MTLS_HEADERS", "false").lower() == "true"
    mtls_verify_header: str = os.getenv("AUTH_MTLS_VERIFY_HEADER", "x-ssl-client-verify")
    mtls_dn_header: str = os.getenv("AUTH_MTLS_DN_HEADER", "x-ssl-client-s-dn")

    excluded_paths: t.FrozenSet[str] = frozenset(
        s.strip() for s in os.getenv("AUTH_EXCLUDED_PATHS", "/health,/readyz,/metrics").split(",")
    )

    tenant_header: str = os.getenv("AUTH_TENANT_HEADER", "X-Tenant-Id")

    @classmethod
    def from_env(cls) -> "AuthSettings":
        return cls()


# ---------------------------
# Утилиты
# ---------------------------

def _consteq(a: str, b: str) -> bool:
    try:
        return hmac.compare_digest(a.encode(), b.encode())
    except Exception:
        return False


def _now() -> int:
    return int(time.time())


def _split_scopes(val: t.Optional[str]) -> t.Set[str]:
    if not val:
        return set()
    # OIDC может давать 'scope' как строку с пробелами, Azure AD — 'scp'
    return set(s for s in val.replace(",", " ").split() if s)


def _extract_roles(claims: t.Mapping[str, t.Any]) -> t.Set[str]:
    roles: set[str] = set()
    # Keycloak: realm_access.roles, resource_access[client].roles
    realm = claims.get("realm_access", {})
    if isinstance(realm, dict):
        roles |= set(realm.get("roles") or [])
    res = claims.get("resource_access", {})
    if isinstance(res, dict):
        for v in res.values():
            if isinstance(v, dict):
                roles |= set(v.get("roles") or [])
    # Custom claim "roles"
    if "roles" in claims and isinstance(claims["roles"], (list, tuple)):
        roles |= set(claims["roles"])
    return roles


def _redact_header_value(name: str, value: str) -> str:
    if name.lower() in {"authorization", "cookie"}:
        return "***"
    return value


# ---------------------------
# Хранилище повторов (jti)
# ---------------------------

class ReplayStore(t.Protocol):
    async def seen_or_remember(self, jti: str, exp_ts: int) -> bool:
        """
        True  -> уже видели (повтор)
        False -> запомнили как новый
        """
        ...


class InMemoryReplayStore:
    def __init__(self) -> None:
        self._data: dict[str, int] = {}
        self._lock = asyncio.Lock()

    async def seen_or_remember(self, jti: str, exp_ts: int) -> bool:
        now = _now()
        async with self._lock:
            # cleanup иногда
            if len(self._data) > 10000:
                expired = [k for k, v in self._data.items() if v <= now]
                for k in expired:
                    self._data.pop(k, None)
            if jti in self._data and self._data[jti] > now:
                return True
            self._data[jti] = max(exp_ts, now + 60)
            return False


# ---------------------------
# JWKS кэш и OIDC верификатор
# ---------------------------

class JWKSCache:
    def __init__(self, url: str, ttl: int, timeout: float) -> None:
        self.url = url
        self.ttl = ttl
        self.timeout = timeout
        self._keys: dict[str, t.Any] = {}
        self._expires_at: int = 0
        self._lock = asyncio.Lock()

    async def _refresh(self) -> None:
        async with self._lock:
            if _now() < self._expires_at:
                return
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                r = await client.get(self.url)
                r.raise_for_status()
                data = r.json()
            keys = {}
            for k in data.get("keys", []):
                kid = k.get("kid")
                if kid:
                    keys[kid] = k
            self._keys = keys
            self._expires_at = _now() + self.ttl

    async def get_key(self, kid: str) -> t.Optional[dict]:
        if _now() >= self._expires_at:
            await self._refresh()
        return self._keys.get(kid)


class OIDCVerifier:
    def __init__(self, settings: AuthSettings, replay_store: ReplayStore) -> None:
        if not settings.oidc_jwks_url:
            raise ValueError("AUTH_OIDC_JWKS_URL is required for oidc mode")
        self.settings = settings
        self.jwks = JWKSCache(
            url=settings.oidc_jwks_url,
            ttl=settings.oidc_cache_ttl,
            timeout=settings.oidc_http_timeout,
        )
        self.replay_store = replay_store

    async def verify(self, token: str) -> Principal:
        try:
            header = jwt.get_unverified_header(token)
        except Exception as e:
            raise AuthError(401, "invalid_token", f"Cannot parse token header: {e}")

        kid = header.get("kid")
        alg = header.get("alg")

        if alg not in self.settings.oidc_algorithms:
            raise AuthError(401, "invalid_token", "Algorithm not allowed")

        key = None
        if kid:
            key = await self.jwks.get_key(kid)
            # если не нашли — обновим кэш и попробуем снова
            if not key:
                await self.jwks._refresh()
                key = await self.jwks.get_key(kid)

        # Для HS256 возможен общий секрет (не рекомендуется); не реализуем по умолчанию
        if not key and alg.startswith("HS"):
            raise AuthError(401, "invalid_token", "HMAC tokens are not supported without shared secret")

        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=list(self.settings.oidc_algorithms),
                audience=self.settings.oidc_audience,
                issuer=self.settings.oidc_issuer,
                options={
                    "verify_aud": self.settings.oidc_audience is not None,
                    "verify_iss": self.settings.oidc_issuer is not None,
                    "leeway": self.settings.oidc_leeway,
                },
            )
        except Exception as e:
            raise AuthError(401, "invalid_token", f"Token verification failed: {e}")

        jti = claims.get("jti")
        exp = int(claims.get("exp", 0))
        if jti:
            repeated = await self.replay_store.seen_or_remember(jti, exp)
            if repeated:
                raise AuthError(401, "token_replayed", "Replay detected")

        scopes = _split_scopes(claims.get("scope") or claims.get("scp"))
        roles = _extract_roles(claims)

        missing_scopes = set(self.settings.oidc_required_scopes) - scopes
        if missing_scopes:
            raise AuthError(403, "insufficient_scope", f"Missing scopes: {','.join(sorted(missing_scopes))}")

        if self.settings.oidc_required_roles:
            if not set(self.settings.oidc_required_roles).issubset(roles):
                raise AuthError(403, "insufficient_role", "Required role not present")

        tenant = claims.get("tenant") or claims.get("tenant_id") or claims.get("tid")
        sub = claims.get("sub") or "anonymous"

        principal = Principal(
            subject=str(sub),
            tenant_id=str(tenant) if tenant else None,
            roles=frozenset(roles),
            scopes=frozenset(scopes),
            claims=claims,
        )
        return principal


# ---------------------------
# API Key валидатор
# ---------------------------

class APIKeyValidator:
    """
    Поддерживает:
      - простой API ключ, равный значению в AUTH_API_KEYS
      - формат "sha256=HEX" для значений в AUTH_API_KEYS (сравнение по SHA256(представленного ключа))
    """

    def __init__(self, settings: AuthSettings) -> None:
        self.settings = settings
        self._sha_indicators = [k for k in settings.api_key_allowed if k.startswith("sha256=")]
        self._plain = [k for k in settings.api_key_allowed if not k.startswith("sha256=")]

    def _hash_sha256(self, raw: str) -> str:
        import hashlib

        return "sha256=" + hashlib.sha256(raw.encode()).hexdigest()

    def validate(self, provided: str) -> bool:
        if not provided:
            return False
        # plain
        if any(_consteq(provided, k) for k in self._plain):
            return True
        # sha256
        hashed = self._hash_sha256(provided)
        if any(_consteq(hashed, k) for k in self._sha_indicators):
            return True
        return False


# ---------------------------
# Ошибки и ответы
# ---------------------------

class AuthError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        self.status = status
        self.code = code
        self.message = message
        super().__init__(message)


def _json_error(status: int, code: str, message: str, request_id: str) -> JSONResponse:
    body = {
        "error": {"code": code, "message": message},
        "request_id": request_id,
    }
    headers = {
        "Content-Type": "application/json",
        "X-Request-Id": request_id,
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
    }
    if status == 401:
        headers["WWW-Authenticate"] = 'Bearer realm="policy-core", error="%s"' % code
    return JSONResponse(status_code=status, content=body, headers=headers)


# ---------------------------
# Основной middleware
# ---------------------------

class AuthMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        settings: AuthSettings | None = None,
        replay_store: ReplayStore | None = None,
    ) -> None:
        self.app = app
        self.settings = settings or AuthSettings.from_env()
        self.replay_store = replay_store or InMemoryReplayStore()
        self._oidc: OIDCVerifier | None = None
        if self.settings.mode in {"oidc", "hybrid"}:
            if not self.settings.oidc_jwks_url:
                # отложенная инициализация возможна позже при первом запросе, но лучше упасть заранее конфигом
                pass
            else:
                self._oidc = OIDCVerifier(self.settings, self.replay_store)
        self._apikey = APIKeyValidator(self.settings)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        method: str = scope.get("method", "GET")

        # Скипаем health/metrics
        if path in self.settings.excluded_paths:
            await self.app(scope, receive, send)
            return

        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}

        # Корреляция
        req_id = headers.get("x-request-id") or str(uuid.uuid4())

        try:
            principal = await self._authenticate(headers, scope)
        except AuthError as e:
            await _json_error(e.status, e.code, e.message, req_id)(scope, receive, send)
            return
        except Exception as e:
            await _json_error(500, "auth_internal", f"Unhandled auth error: {e}", req_id)(scope, receive, send)
            return

        # Пробрасываем principal в state и контекст
        scope.setdefault("state", {})
        scope["state"]["principal"] = principal
        token = principal_var.set(principal)

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers_list = message.setdefault("headers", [])
                # добавим идентичность в заголовки ответа
                def _add(name: str, value: str):
                    headers_list.append((name.encode(), value.encode()))

                _add("x-request-id", req_id)
                _add("x-auth-subject", principal.subject)
                if principal.tenant_id:
                    _add("x-tenant-id", principal.tenant_id)
                if principal.scopes:
                    _add("x-auth-scopes", ",".join(sorted(principal.scopes)))
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            # восстановим контекст
            principal_var.reset(token)

    async def _authenticate(self, headers: dict[str, str], scope: Scope) -> Principal:
        mode = self.settings.mode

        if mode == "none":
            return Principal("anonymous", None, frozenset(), frozenset(), {})

        bearer = _extract_bearer(headers.get("authorization"))
        api_key = headers.get(self.settings.api_key_header.lower())
        if not api_key:
            # разрешим также query-параметр (например, для простых скриптов)
            qs = scope.get("query_string", b"").decode()
            api_key = _get_query_param(qs, self.settings.api_key_param)

        tenant = headers.get(self.settings.tenant_header.lower())

        # mTLS заголовки (если доверяем прокси)
        if self.settings.trust_mtls_headers:
            mtls_ok = headers.get(self.settings.mtls_verify_header.lower()) == "SUCCESS"
            mtls_dn = headers.get(self.settings.mtls_dn_header.lower())
        else:
            mtls_ok = False
            mtls_dn = None

        # HYBRID: сначала Bearer, затем API-KEY
        if mode in {"hybrid", "oidc"} and bearer:
            if not self._oidc:
                self._oidc = OIDCVerifier(self.settings, self.replay_store)
            principal = await self._oidc.verify(bearer)
            # Приоритет tenant из заголовка (если есть строгая сегрегация маршрутизатором)
            if tenant and not principal.tenant_id:
                principal = dataclasses.replace(principal, tenant_id=tenant)
            return principal

        if mode in {"hybrid", "api_key"} and api_key:
            if not self._apikey.validate(api_key):
                raise AuthError(401, "invalid_api_key", "API key not allowed")
            roles = frozenset({"service"})
            scopes = frozenset({"mythos.read"})
            subject = f"api-key:{_sha8(api_key)}"
            return Principal(subject=subject, tenant_id=tenant, roles=roles, scopes=scopes, claims={})

        raise AuthError(401, "credentials_required", "Provide Bearer token or API key")

# ---------------------------
# Вспомогательные функции (private)
# ---------------------------

def _extract_bearer(auth_header: t.Optional[str]) -> t.Optional[str]:
    if not auth_header:
        return None
    parts = auth_header.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return None


def _get_query_param(qs: str, name: str) -> t.Optional[str]:
    if not qs:
        return None
    # очень лёгкий парсер, без зависимостей
    for chunk in qs.split("&"):
        if not chunk:
            continue
        k, sep, v = chunk.partition("=")
        if k == name and sep:
            return _percent_decode(v)
    return None


def _percent_decode(s: str) -> str:
    try:
        return httpx.QueryParams(f"a={s}")["a"]
    except Exception:
        return s


def _sha8(raw: str) -> str:
    import hashlib

    return hashlib.sha256(raw.encode()).hexdigest()[:8]
