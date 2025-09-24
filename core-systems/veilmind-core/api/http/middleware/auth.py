# -*- coding: utf-8 -*-
from __future__ import annotations

import asyncio
import base64
import functools
import hmac
import hashlib
import ipaddress
import json
import logging
import re
import time
from dataclasses import dataclass, asdict
from typing import Any, Awaitable, Callable, Dict, Iterable, Optional, Tuple, Union

from starlette.datastructures import Headers
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

# Логгер middleware
log = logging.getLogger("veilmind.auth")

# ---------------------------------------------------------------------------
# Типы и интерфейсы
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SecurityContext:
    method: str                      # "bearer", "api_key", "hmac"
    subject: str                     # sub / key id
    tenant: Optional[str]
    scopes: Tuple[str, ...] = ()
    claims: Dict[str, Any] = None    # сырые подтвержденные атрибуты (JWT claims и т.п.)
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    token_id: Optional[str] = None   # jti/nonce
    issued_at: Optional[int] = None  # iat/ts
    auth_strength: str = "strong"    # "strong"|"medium"|"weak"

    def as_headers(self) -> Dict[str, str]:
        # Канареечные audit‑заголовки вниз по стеку
        return {
            "X-Auth-Method": self.method,
            "X-Auth-Subject": self.subject,
            "X-Auth-Tenant": self.tenant or "",
            "X-Auth-Scopes": " ".join(self.scopes) if self.scopes else "",
            "X-Auth-Token-ID": self.token_id or "",
            "X-Auth-Issued-At": str(self.issued_at or ""),
            "X-Auth-Strength": self.auth_strength,
        }

# JWT верификатор: должен бросать исключение при ошибке и возвращать (claims, token_id, subject, scopes, tenant, iat)
JWTVerifier = Callable[[str, Dict[str, Any]], Awaitable[Tuple[Dict[str, Any], Optional[str], str, Tuple[str, ...], Optional[str], Optional[int]]]]

# API‑ключ резолвер: вернуть (valid:bool, subject:str, tenant:str|None, scopes:tuple[str,...])
APIKeyResolver = Callable[[str], Awaitable[Tuple[bool, Optional[str], Optional[str], Tuple[str, ...]]]]

# HMAC‑секрет резолвер: вернуть (secret: bytes | None) по keyId/tenant
HMACSecretResolver = Callable[[str, Optional[str]], Awaitable[Optional[bytes]]]

# Replay‑кэш интерфейс (можно подменить на Redis)
class ReplayCache:
    def __init__(self, ttl_seconds: int = 300, max_items: int = 100_000) -> None:
        self._ttl = ttl_seconds
        self._max = max_items
        self._store: Dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def add_if_absent(self, key: str) -> bool:
        now = time.time()
        async with self._lock:
            # Очистка по размеру/времени (lazy)
            if len(self._store) > self._max:
                cutoff = now - self._ttl
                for k, t0 in list(self._store.items())[: self._max // 10]:
                    if t0 < cutoff:
                        self._store.pop(k, None)
            if key in self._store and now - self._store[key] <= self._ttl:
                return False
            self._store[key] = now
            return True

# ---------------------------------------------------------------------------
# Исключения
# ---------------------------------------------------------------------------

class AuthError(Exception):
    def __init__(self, code: str, desc: str, status: int = 401) -> None:
        super().__init__(desc)
        self.code = code
        self.desc = desc
        self.status = status

# ---------------------------------------------------------------------------
# Конфигурация middleware
# ---------------------------------------------------------------------------

@dataclass
class AuthConfig:
    # Общие
    enabled: bool = True
    allowed_clock_skew: int = 120  # сек
    tenant_header: str = "X-Tenant"
    client_ip_headers: Tuple[str, ...] = ("X-Forwarded-For", "X-Real-IP")
    trusted_proxy_nets: Tuple[str, ...] = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    enforce_mtls_header: Optional[str] = None  # например "X-SSL-Client-Verify: SUCCESS"
    # Bearer JWT
    allow_bearer: bool = True
    require_bearer_scopes: Tuple[str, ...] = ()
    # API‑ключ
    allow_api_key: bool = True
    api_key_header: str = "X-API-Key"
    # HMAC (date-based)
    allow_hmac: bool = True
    hmac_id_header: str = "X-Auth-Key-Id"
    hmac_ts_header: str = "X-Auth-Timestamp"  # epoch seconds
    hmac_sig_header: str = "X-Auth-Signature" # base64(hmac_sha256(key, signing_string))
    hmac_bind_headers: Tuple[str, ...] = ("content-type",)
    hmac_allow_body: bool = True
    # Anti‑replay
    replay_ttl_seconds: int = 300
    # Трассировка
    emit_audit_headers: bool = True

# ---------------------------------------------------------------------------
# Утилиты
# ---------------------------------------------------------------------------

def _client_ip_from_headers(headers: Headers, cfg: AuthConfig) -> Optional[str]:
    ip: Optional[str] = None
    for h in cfg.client_ip_headers:
        v = headers.get(h)
        if not v:
            continue
        # X-Forwarded-For: берем первый не‑приватный IP
        parts: Iterable[str] = (p.strip() for p in v.split(","))
        for cand in parts:
            try:
                ipaddress.ip_address(cand)
                ip = cand
                break
            except Exception:
                continue
        if ip:
            break
    return ip

def _is_trusted_proxy(addr: str, cfg: AuthConfig) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        nets = [ipaddress.ip_network(n) for n in cfg.trusted_proxy_nets]
        return any(ip in n for n in nets)
    except Exception:
        return False

def _normalize_bearer(authz: str) -> Optional[str]:
    if not authz:
        return None
    m = re.match(r"(?i)Bearer\s+(.+)$", authz.strip())
    return m.group(1).strip() if m else None

def _json_error(status: int, code: str, desc: str, realm: str = "veilmind") -> JSONResponse:
    # RFC 6750‑совместимый WWW-Authenticate
    hdr = f'Bearer realm="{realm}", error="{code}", error_description="{desc}"'
    return JSONResponse({"error": code, "error_description": desc}, status_code=status, headers={"WWW-Authenticate": hdr})

def _safe_b64(s: bytes) -> str:
    return base64.b64encode(s).decode("ascii")

# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

class AuthMiddleware(BaseHTTPMiddleware):
    """
    Zero‑Trust аутентификация с несколькими стратегиями.

    Порядок:
      1) Bearer JWT (если включен)
      2) API‑ключ (если включен)
      3) HMAC (если включен)

    При успехе записывает SecurityContext в request.state.security.
    """

    def __init__(
        self,
        app,
        *,
        config: AuthConfig,
        jwt_verifier: Optional[JWTVerifier] = None,
        api_key_resolver: Optional[APIKeyResolver] = None,
        hmac_secret_resolver: Optional[HMACSecretResolver] = None,
        replay_cache: Optional[ReplayCache] = None,
    ):
        super().__init__(app)
        self.cfg = config
        self.jwt_verifier = jwt_verifier
        self.api_key_resolver = api_key_resolver
        self.hmac_secret_resolver = hmac_secret_resolver
        self.replay_cache = replay_cache or ReplayCache(ttl_seconds=config.replay_ttl_seconds)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if not self.cfg.enabled:
            return await call_next(request)

        try:
            # mTLS Enforce (если за прокси — передан верификационный заголовок)
            if self.cfg.enforce_mtls_header:
                if request.headers.get(self.cfg.enforce_mtls_header) not in ("SUCCESS", "Verified", "OK", "true"):
                    raise AuthError("mtls_required", "mTLS verification failed or missing", 401)

            sc = await self._authenticate(request)

            # Привязка IP/UA в контексте
            h = request.headers
            client_ip = _client_ip_from_headers(h, self.cfg) or request.client.host if request.client else None
            # Если реальный клиент не из доверенной сети, но XFF присутствует — это может быть спуфинг
            if client_ip and h.get("X-Forwarded-For") and not _is_trusted_proxy(request.client.host if request.client else "", self.cfg):
                log.warning("Untrusted proxy in front of service; X-Forwarded-For may be spoofed")
            sc = SecurityContext(
                method=sc.method, subject=sc.subject, tenant=sc.tenant, scopes=sc.scopes,
                claims=sc.claims or {}, client_ip=client_ip, user_agent=h.get("User-Agent"),
                token_id=sc.token_id, issued_at=sc.issued_at, auth_strength=sc.auth_strength
            )

            # Запишем контекст
            request.state.security = sc

            resp = await call_next(request)

            # Канареечные заголовки для аудита даем только на 2xx/3xx
            if self.cfg.emit_audit_headers and 200 <= resp.status_code < 400:
                for k, v in sc.as_headers().items():
                    if v:
                        resp.headers.setdefault(k, v)
            return resp

        except AuthError as e:
            log.info("AuthError: %s - %s", e.code, e.desc)
            return _json_error(e.status, e.code, e.desc)
        except Exception as e:
            log.exception("Auth middleware failure: %s", e)
            return _json_error(401, "server_error", "authentication processing failure")

    # -------------------- Стратегии --------------------

    async def _authenticate(self, request: Request) -> SecurityContext:
        h = request.headers
        tenant = h.get(self.cfg.tenant_header)

        # 1) Bearer
        if self.cfg.allow_bearer and self.jwt_verifier:
            token = _normalize_bearer(h.get("Authorization", ""))
            if token:
                claims, jti, subj, scopes, tnt, iat = await self._verify_bearer(token, tenant)
                return SecurityContext(
                    method="bearer",
                    subject=subj,
                    tenant=tnt or tenant,
                    scopes=scopes,
                    claims=claims,
                    token_id=jti,
                    issued_at=iat,
                    auth_strength="strong",
                )

        # 2) API‑ключ
        if self.cfg.allow_api_key and self.api_key_resolver:
            api_key = h.get(self.cfg.api_key_header)
            if api_key:
                valid, subj, tnt, scopes = await self.api_key_resolver(api_key)
                if not valid:
                    raise AuthError("invalid_token", "invalid API key", 401)
                return SecurityContext(
                    method="api_key",
                    subject=subj or "unknown",
                    tenant=tnt or tenant,
                    scopes=scopes or (),
                    claims={"api_key_id": subj} if subj else {},
                    token_id=None,
                    issued_at=None,
                    auth_strength="medium",
                )

        # 3) HMAC
        if self.cfg.allow_hmac and self.hmac_secret_resolver:
            key_id = h.get(self.cfg.hmac_id_header)
            ts = h.get(self.cfg.hmac_ts_header)
            sig = h.get(self.cfg.hmac_sig_header)
            if key_id and ts and sig:
                ctx = await self._verify_hmac(request, tenant, key_id, ts, sig)
                return ctx

        # Если явно присутствовал Authorization но не прошел — ошибка RFC 6750
        if h.get("Authorization"):
            raise AuthError("invalid_token", "invalid bearer token", 401)
        # Иначе — нет учетных данных
        raise AuthError("invalid_request", "missing credentials", 401)

    # -------------------- Bearer JWT --------------------

    async def _verify_bearer(self, token: str, tenant_hdr: Optional[str]) -> Tuple[Dict[str, Any], Optional[str], str, Tuple[str, ...], Optional[str], Optional[int]]:
        assert self.jwt_verifier is not None
        # Передаем контекст в верификатор (можно использовать для audience/issuer)
        ctx = {"tenant_hint": tenant_hdr, "require_scopes": self.cfg.require_bearer_scopes}
        claims, jti, subj, scopes, tenant, iat = await self.jwt_verifier(token, ctx)

        # Инварианты
        if not subj:
            raise AuthError("invalid_token", "sub missing", 401)
        if self.cfg.require_bearer_scopes:
            lack = set(self.cfg.require_bearer_scopes) - set(scopes or ())
            if lack:
                raise AuthError("insufficient_scope", f"required scopes missing: {','.join(sorted(lack))}", 403)

        # clock skew / jti
        now = int(time.time())
        if "exp" in claims and int(claims["exp"]) + self.cfg.allowed_clock_skew < now:
            raise AuthError("invalid_token", "token expired", 401)
        if "nbf" in claims and int(claims["nbf"]) - self.cfg.allowed_clock_skew > now:
            raise AuthError("invalid_token", "token not yet valid", 401)

        # anti‑replay по jti
        if jti:
            if not await self.replay_cache.add_if_absent(f"jwt:{jti}"):
                raise AuthError("invalid_token", "replayed token", 401)

        return claims, jti, subj, scopes or (), tenant, iat

    # -------------------- HMAC --------------------

    async def _verify_hmac(self, request: Request, tenant_hdr: Optional[str], key_id: str, ts: str, sig_b64: str) -> SecurityContext:
        assert self.hmac_secret_resolver is not None
        try:
            ts_i = int(ts)
        except Exception:
            raise AuthError("invalid_request", "invalid timestamp", 401)
        now = int(time.time())
        if abs(now - ts_i) > self.cfg.allowed_clock_skew:
            raise AuthError("invalid_token", "timestamp skew too large", 401)

        secret = await self.hmac_secret_resolver(key_id, tenant_hdr)
        if not secret:
            raise AuthError("invalid_token", "unknown key id", 401)

        body = await (request.body() if self.cfg.hmac_allow_body else b"")
        # Строка подписи: METHOD \n PATH \n TS \n LOWER(headers...) \n SHA256(body)
        hashed_body = hashlib.sha256(body).hexdigest()
        bind_values = []
        for name in self.cfg.hmac_bind_headers:
            bind_values.append(f"{name.lower()}={request.headers.get(name, '').strip()}")
        signing_string = "\n".join(
            [
                request.method.upper(),
                request.url.path,
                str(ts_i),
                ";".join(bind_values),
                hashed_body,
            ]
        ).encode("utf-8")

        calc = hmac.new(secret, signing_string, hashlib.sha256).digest()
        try:
            supplied = base64.b64decode(sig_b64, validate=True)
        except Exception:
            raise AuthError("invalid_token", "invalid signature encoding", 401)

        if not hmac.compare_digest(calc, supplied):
            raise AuthError("invalid_token", "signature mismatch", 401)

        # anti‑replay по (key_id, ts, body_hash)
        replay_key = f"hmac:{key_id}:{ts_i}:{hashed_body}"
        if not await self.replay_cache.add_if_absent(replay_key):
            raise AuthError("invalid_token", "replayed request", 401)

        tenant = tenant_hdr
        return SecurityContext(
            method="hmac",
            subject=key_id,
            tenant=tenant,
            scopes=(),
            claims={"ts": ts_i, "body_sha256": hashed_body},
            token_id=f"{key_id}:{ts_i}",
            issued_at=ts_i,
            auth_strength="strong",
        )

# ---------------------------------------------------------------------------
# Пример интеграции с FastAPI
# ---------------------------------------------------------------------------

# Пример адаптера JWT‑верификатора (обертка над вашим IdP‑адаптером)
async def example_jwt_verifier(token: str, ctx: Dict[str, Any]) -> Tuple[Dict[str, Any], Optional[str], str, Tuple[str, ...], Optional[str], Optional[int]]:
    """
    Реализуйте через ваш IdP‑адаптер: проверка подписи, iss/aud, nbf/exp/iat.
    Возвращайте: (claims, jti, sub, scopes, tenant, iat)
    """
    # Псевдо‑пример — обязательно замените на реальную верификацию!
    # Здесь только каркас и базовая структура.
    try:
        # your_idp = ...
        # claims = await your_idp.verify(token, audience=..., issuer=...)
        # Ниже — безопасное значение-заглушка:
        claims: Dict[str, Any] = {"sub": "anonymous", "iat": int(time.time()), "jti": None}
        sub = str(claims.get("sub", ""))
        jti = claims.get("jti")
        scopes: Tuple[str, ...] = tuple(claims.get("scope", "").split()) if claims.get("scope") else ()
        tenant = claims.get("tenant")
        iat = claims.get("iat")
        if not sub:
            raise ValueError("sub missing")
        return claims, jti, sub, scopes, tenant, iat
    except Exception as e:
        raise AuthError("invalid_token", f"jwt verification failed: {e}", 401)

# Пример резолвера API‑ключей
async def example_api_key_resolver(api_key: str) -> Tuple[bool, Optional[str], Optional[str], Tuple[str, ...]]:
    # Проверьте хранилище ключей; здесь — только каркас.
    # Верните (valid, subject, tenant, scopes)
    return (False, None, None, ())

# Пример резолвера HMAC‑секретов
async def example_hmac_secret_resolver(key_id: str, tenant: Optional[str]) -> Optional[bytes]:
    # Верните секрет по key_id/tenant; здесь — каркас.
    return None

# Фабрика для удобной установки middleware
def auth_middleware_factory(
    *,
    config: Optional[AuthConfig] = None,
    jwt_verifier: Optional[JWTVerifier] = None,
    api_key_resolver: Optional[APIKeyResolver] = None,
    hmac_secret_resolver: Optional[HMACSecretResolver] = None,
    replay_cache: Optional[ReplayCache] = None,
) -> Callable:
    cfg = config or AuthConfig()
    def installer(app):
        app.add_middleware(
            AuthMiddleware,
            config=cfg,
            jwt_verifier=jwt_verifier,
            api_key_resolver=api_key_resolver,
            hmac_secret_resolver=hmac_secret_resolver,
            replay_cache=replay_cache,
        )
        return app
    return installer

# ---------------------------------------------------------------------------
# Хелперы для эндпоинтов (декораторы/гарды)
# ---------------------------------------------------------------------------

def require_scopes(*needed: str):
    """
    Простой guard для эндпоинтов FastAPI/Starlette.
    Пример:
        @app.get("/admin")
        @require_scopes("admin:read")
        async def admin(request: Request): ...
    """
    need = set(needed)
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Ищем Request в аргументах
            req: Optional[Request] = next((a for a in args if isinstance(a, Request)), None) or kwargs.get("request")
            if req is None:
                raise RuntimeError("Request object is required")
            sc: SecurityContext = getattr(req.state, "security", None)
            if sc is None:
                return _json_error(401, "invalid_request", "no security context")
            have = set(sc.scopes or ())
            if not need.issubset(have):
                return _json_error(403, "insufficient_scope", f"required scopes: {','.join(sorted(need))}")
            return await func(*args, **kwargs)
        return wrapper
    return decorator
