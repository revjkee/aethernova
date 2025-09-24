# -*- coding: utf-8 -*-
"""
ASGI Auth Middleware for ledger-core
- Bearer JWT (OIDC/JWKS) with caching & rotation
- API Key (header/query)
- Optional HMAC signature verification (for webhooks)
- Correlation IDs (X-Request-Id / traceparent)
- Deny-by-default, precise 401/403 with RFC-compliant headers
- Hooks for metrics/audit and rate-limiting
Compatible with Starlette / FastAPI / any ASGI app.

Dependencies (minimal):
    pip install httpx pydantic cryptography python-jose[cryptography]

If you use FastAPI, add:
    app.add_middleware(AuthMiddleware, config=AuthConfig())

© MIT
"""
from __future__ import annotations

import asyncio
import base64
import hmac
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union

import httpx
from jose import jwk, jwt
from jose.utils import base64url_decode
from pydantic import BaseModel, Field, AnyHttpUrl, ValidationError, validator

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Receive, Scope, Send

# ============================ Конфигурация ============================

class AuthConfig(BaseModel):
    # Общие
    enabled: bool = Field(default=True)
    environment: str = Field(default=os.getenv("APP_ENV", "staging"))
    service_name: str = Field(default="ledger-core")

    # Корреляция
    request_id_header: str = Field(default="X-Request-Id")
    traceparent_header: str = Field(default="traceparent")
    generate_request_id_if_missing: bool = Field(default=True)

    # Allowlist (пути/методы, которые не требуют аутентификации)
    allowlist_paths: List[str] = Field(default_factory=lambda: [r"^/health$", r"^/ready$", r"^/metrics$"])
    allowlist_methods: List[str] = Field(default_factory=lambda: ["GET"])

    # JWT/OIDC
    oidc_issuer: Optional[AnyHttpUrl] = Field(default=os.getenv("OIDC_ISSUER"))
    oidc_audience: Optional[str] = Field(default=os.getenv("OIDC_AUDIENCE"))
    jwks_uri: Optional[AnyHttpUrl] = Field(default=os.getenv("OIDC_JWKS_URI"))
    required_scopes: List[str] = Field(default_factory=list)
    accept_algorithms: List[str] = Field(default_factory=lambda: ["RS256", "ES256"])
    leeway_seconds: int = Field(default=60)  # clock skew
    jwks_ttl_seconds: int = Field(default=900)  # 15 min
    jwks_http_timeout_seconds: float = Field(default=3.0)

    # API Key
    api_key_header: str = Field(default="X-API-Key")
    api_key_query: str = Field(default="api_key")
    valid_api_keys: List[str] = Field(default_factory=lambda: _split_env("API_KEYS"))  # comma-separated

    # HMAC (e.g., webhooks)
    hmac_header: str = Field(default="X-Signature")
    hmac_secret_b64: Optional[str] = Field(default=os.getenv("HMAC_SECRET_B64"))
    hmac_alg: str = Field(default="sha256")  # sha256|sha512
    hmac_tolerance_seconds: int = Field(default=300)  # optional if signed timestamp present

    # Авторизация (RBAC/ABAC) — плагины/крючки
    role_claim: str = Field(default="roles")
    subject_claim: str = Field(default="sub")

    # Безопасность заголовков ответа
    add_security_headers: bool = Field(default=True)

    # Метрики/Аудит — функции‑крючки (установите при инициализации)
    metrics_hook: Optional[Callable[[str, Dict[str, Any]], None]] = None
    audit_hook: Optional[Callable[[str, Dict[str, Any]], None]] = None
    rate_limit_hook: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = None

    @validator("jwks_uri", always=True)
    def _set_default_jwks(cls, v, values):
        # Если JWKS не указан — пробуем .well-known/openid-configuration
        if v is None and (iss := values.get("oidc_issuer")):
            return AnyHttpUrl(str(iss).rstrip("/") + "/.well-known/jwks.json")
        return v

def _split_env(name: str) -> List[str]:
    raw = os.getenv(name, "")
    return [x.strip() for x in raw.split(",") if x.strip()]

# ============================ Исключения/ответы ============================

class AuthError(Exception):
    def __init__(self, status_code: int, code: str, message: str, www_authenticate: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.www_authenticate = www_authenticate

async def _send_error(send: Send, status: int, payload: Dict[str, Any], www_authenticate: Optional[str] = None) -> None:
    body = json.dumps(payload).encode("utf-8")
    headers = [(b"content-type", b"application/json")]
    if www_authenticate:
        headers.append((b"www-authenticate", www_authenticate.encode("utf-8")))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})

# ============================ JWKS Кэш ============================

@dataclass
class _JWKSCache:
    keys: Dict[str, Dict[str, Any]]
    fetched_at: float

class _JWKSClient:
    def __init__(self, jwks_uri: str, timeout: float, ttl: int):
        self._jwks_uri = jwks_uri
        self._timeout = timeout
        self._ttl = ttl
        self._cache: Optional[_JWKSCache] = None
        self._lock = asyncio.Lock()

    async def get_key(self, kid: str) -> Dict[str, Any]:
        now = time.time()
        if self._cache and (now - self._cache.fetched_at) < self._ttl and kid in self._cache.keys:
            return self._cache.keys[kid]

        async with self._lock:
            # double-check после захвата
            if self._cache and (now - self._cache.fetched_at) < self._ttl and kid in self._cache.keys:
                return self._cache.keys[kid]
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                r = await client.get(self._jwks_uri)
                r.raise_for_status()
                data = r.json()
            keys = {k["kid"]: k for k in data.get("keys", []) if "kid" in k}
            self._cache = _JWKSCache(keys=keys, fetched_at=time.time())
            if kid not in keys:
                raise AuthError(401, "invalid_token", "Unknown key id (kid)", 'Bearer realm="api", error="invalid_token"')
            return keys[kid]

# ============================ Утилиты ============================

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{8,128}$")
def _get_request_id(headers: Headers, cfg: AuthConfig) -> str:
    rid = headers.get(cfg.request_id_header)
    if rid and _REQUEST_ID_RE.match(rid):
        return rid
    # traceparent может содержать trace-id
    tp = headers.get(cfg.traceparent_header)
    if tp and isinstance(tp, str) and "-" in tp:
        parts = tp.split("-")
        if len(parts) >= 2 and len(parts[1]) == 32:
            return parts[1]
    if cfg.generate_request_id_if_missing:
        # простая монотонная генерация совместимая с RFC4122 v4 (нестрогая)
        import uuid
        return uuid.uuid4().hex
    return "unknown"

def _secure_compare(a: str, b: str) -> bool:
    try:
        return hmac.compare_digest(a, b)
    except Exception:
        return False

def _extract_api_key(headers: Headers, query_string: bytes, cfg: AuthConfig) -> Optional[str]:
    k = headers.get(cfg.api_key_header)
    if k:
        return k.strip()
    if query_string:
        from urllib.parse import parse_qs
        q = parse_qs(query_string.decode("utf-8"), keep_blank_values=False)
        vals = q.get(cfg.api_key_query)
        if vals:
            return vals[0]
    return None

def _verify_hmac(headers: Headers, body: bytes, cfg: AuthConfig) -> bool:
    if not cfg.hmac_secret_b64:
        return False
    sig = headers.get(cfg.hmac_header)
    if not sig:
        return False
    try:
        secret = base64.b64decode(cfg.hmac_secret_b64)
    except Exception:
        return False
    alg = cfg.hmac_alg.lower()
    import hashlib
    digestmod = {"sha256": hashlib.sha256, "sha512": hashlib.sha512}.get(alg)
    if not digestmod:
        return False
    mac = hmac.new(secret, body, digestmod).hexdigest()
    return _secure_compare(sig.lower(), mac.lower())

def _path_allowed(path: str, method: str, cfg: AuthConfig) -> bool:
    for rx in cfg.allowlist_paths:
        if re.match(rx, path):
            if method.upper() in cfg.allowlist_methods:
                return True
    return False

# ============================ Контекст аутентификации ============================

@dataclass
class Principal:
    subject: str
    roles: Tuple[str, ...]
    scopes: Tuple[str, ...]
    claims: Dict[str, Any]
    method: str  # "jwt" | "api-key" | "hmac"

AUTH_SCOPE_KEY = "auth.principal"
REQUEST_ID_SCOPE_KEY = "request.id"

def _set_response_security_headers(headers: MutableHeaders) -> None:
    headers.setdefault("X-Content-Type-Options", "nosniff")
    headers.setdefault("X-Frame-Options", "DENY")
    headers.setdefault("Referrer-Policy", "no-referrer")
    headers.setdefault("Content-Security-Policy", "default-src 'none'")
    headers.setdefault("Permissions-Policy", "interest-cohort=()")

# ============================ Основное middleware ============================

class AuthMiddleware:
    def __init__(self, app: ASGIApp, config: Optional[AuthConfig] = None):
        self.app = app
        self.cfg = config or AuthConfig()
        self._jwks = _JWKSClient(
            jwks_uri=str(self.cfg.jwks_uri) if self.cfg.jwks_uri else "",
            timeout=self.cfg.jwks_http_timeout_seconds,
            ttl=self.cfg.jwks_ttl_seconds,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if not self.cfg.enabled or scope["type"] != "http":
            return await self.app(scope, receive, send)

        headers = Headers(scope=scope)
        method = scope.get("method", "GET")
        path = scope.get("path", "/")
        request_id = _get_request_id(headers, self.cfg)
        scope[REQUEST_ID_SCOPE_KEY] = request_id

        # Allowlist: health/metrics без аутентификации
        if _path_allowed(path, method, self.cfg):
            async def send_wrapped(event):
                if event["type"] == "http.response.start" and self.cfg.add_security_headers:
                    mh = MutableHeaders(raw=event.setdefault("headers", []))
                    _set_response_security_headers(mh)
                    mh.setdefault("X-Request-Id", request_id)
                await send(event)
            return await self.app(scope, receive, send_wrapped)

        # Аутентификация
        try:
            principal = await self._authenticate(scope, receive)
            scope[AUTH_SCOPE_KEY] = principal
            # Троттлинг (необязательно)
            if self.cfg.rate_limit_hook:
                await self.cfg.rate_limit_hook({
                    "subject": principal.subject,
                    "method": method,
                    "path": path,
                    "roles": principal.roles,
                    "request_id": request_id,
                })
        except AuthError as e:
            payload = {
                "error": e.code,
                "error_description": e.message,
                "request_id": request_id,
            }
            return await _send_error(send, e.status_code, payload, e.www_authenticate)

        # Авторизация (RBAC/ABAC крючок можно добавить здесь при необходимости)

        async def send_wrapped(event):
            if event["type"] == "http.response.start" and self.cfg.add_security_headers:
                mh = MutableHeaders(raw=event.setdefault("headers", []))
                _set_response_security_headers(mh)
                mh.setdefault("X-Request-Id", request_id)
            await send(event)

        return await self.app(scope, receive, send_wrapped)

    async def _authenticate(self, scope: Scope, receive: Receive) -> Principal:
        headers = Headers(scope=scope)
        query_string: bytes = scope.get("query_string", b"")
        authz = headers.get("authorization")
        body_bytes = await _peek_body(receive)

        # 1) JWT Bearer
        if authz and authz.lower().startswith("bearer "):
            token = authz.split(" ", 1)[1].strip()
            return await self._auth_jwt(token)

        # 2) API Key
        api_key = _extract_api_key(headers, query_string, self.cfg)
        if api_key:
            if api_key in self.cfg.valid_api_keys:
                claims = {"api_key": True, "iss": "api-key"}
                return Principal(subject="api-key", roles=("service",), scopes=(), claims=claims, method="api-key")
            raise AuthError(401, "invalid_token", "Invalid API key", 'Bearer realm="api", error="invalid_token"')

        # 3) HMAC (webhooks)
        if _verify_hmac(headers, body_bytes, self.cfg):
            claims = {"hmac": True, "iss": "hmac"}
            return Principal(subject="hmac", roles=("webhook",), scopes=(), claims=claims, method="hmac")

        # Ничего не подошло
        raise AuthError(401, "invalid_token", "Missing or invalid credentials",
                        'Bearer realm="api", error="invalid_token", error_description="credential required"')

    async def _auth_jwt(self, token: str) -> Principal:
        # Заголовок токена (kid/alg)
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            alg = header.get("alg")
        except Exception:
            raise AuthError(401, "invalid_token", "Malformed token header", 'Bearer realm="api", error="invalid_token"')

        if alg not in self.cfg.accept_algorithms:
            raise AuthError(401, "invalid_token", "Unsupported alg", 'Bearer realm="api", error="invalid_token"')

        if not self.cfg.jwks_uri:
            raise AuthError(500, "server_error", "JWKS URI not configured")

        # Ключ из JWKS
        jwk_dict = await self._jwks.get_key(kid)
        public_key = jwk.construct(jwk_dict)

        # Подпись
        try:
            # jose.verify_signature — внутри jwt.decode проверяет подпись и exp/nbf
            claims = jwt.decode(
                token,
                public_key.to_pem().decode("utf-8") if hasattr(public_key, "to_pem") else public_key,
                algorithms=self.cfg.accept_algorithms,
                audience=self.cfg.oidc_audience,
                issuer=str(self.cfg.oidc_issuer) if self.cfg.oidc_issuer else None,
                options={
                    "verify_aud": bool(self.cfg.oidc_audience),
                    "verify_iss": bool(self.cfg.oidc_issuer),
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "leeway": self.cfg.leeway_seconds,
                },
            )
        except Exception as e:
            raise AuthError(401, "invalid_token", f"JWT verification failed: {e}", 'Bearer realm="api", error="invalid_token"')

        # Scopes/Roles
        scopes = _extract_scopes(claims)
        roles = _extract_roles(claims, self.cfg.role_claim)
        if self.cfg.required_scopes and not set(self.cfg.required_scopes).issubset(scopes):
            raise AuthError(403, "insufficient_scope", "Required scopes missing",
                            f'Bearer realm="api", error="insufficient_scope", scope="{ " ".join(self.cfg.required_scopes) }"')

        subject = str(claims.get(self.cfg.subject_claim) or claims.get("sub") or "anonymous")
        return Principal(subject=subject, roles=tuple(sorted(roles)), scopes=tuple(sorted(scopes)),
                         claims=claims, method="jwt")

# ============================ Вспомогательные функции ============================

def _extract_scopes(claims: Mapping[str, Any]) -> set:
    scopes: set = set()
    # RFC 8693 / OAuth — scope как строка
    if "scope" in claims and isinstance(claims["scope"], str):
        scopes |= set(claims["scope"].split())
    # OIDC: scp как список
    if "scp" in claims and isinstance(claims["scp"], (list, tuple)):
        scopes |= set(map(str, claims["scp"]))
    return scopes

def _extract_roles(claims: Mapping[str, Any], role_claim: str) -> set:
    roles: set = set()
    v = claims.get(role_claim)
    if isinstance(v, str):
        roles |= set(v.split(","))
    elif isinstance(v, (list, tuple)):
        roles |= set(map(str, v))
    # Keycloak/standard realm_access
    ra = claims.get("realm_access", {})
    if isinstance(ra, dict) and "roles" in ra:
        roles |= set(map(str, ra["roles"] or []))
    return roles

async def _peek_body(receive: Receive) -> bytes:
    """
    Без изменения протокола читаем body и возвращаем его заново в пайплайн.
    """
    body = b""
    more = True
    messages: List[Dict[str, Any]] = []
    while more:
        message = await receive()
        messages.append(message)
        if message["type"] == "http.request":
            body += message.get("body", b"")
            more = message.get("more_body", False)
        else:
            more = False

    # Восстанавливаем поток
    async def _replay():
        for m in messages:
            yield m

    it = _replay()

    async def _receive_again():
        try:
            return await it.__anext__()
        except StopAsyncIteration:
            return {"type": "http.request", "body": b"", "more_body": False}

    # Подменяем receive в вызывающем scope — это корректно в контексте middleware
    # (в Starlette/FastAPI тело обычно читается уже после middleware)
    # В нашем случае мы возвращаем _receive_again вызывающей цепочке.
    def _patch_receive(scope: Scope, new_receive: Receive):
        scope["_receive"] = new_receive

    # Патчим для текущего запроса
    _patch_receive(scope, _receive_again)
    return body
