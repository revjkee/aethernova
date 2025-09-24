from __future__ import annotations

import base64
import functools
import hashlib
import hmac
import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Set, Tuple, Union

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

# Опционально: RS256/JWKS через cryptography, если доступно
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.hazmat.backends import default_backend  # noqa
    _CRYPTO_OK = True
except Exception:  # cryptography отсутствует — RS256 будет недоступен
    _CRYPTO_OK = False

# Опционально: OpenTelemetry для трассировки
try:
    from opentelemetry import trace
    _TRACER = trace.get_tracer(__name__)
except Exception:
    _TRACER = None

log = logging.getLogger("oblivionvault.auth")


# =========================
# УТИЛИТЫ
# =========================

def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _json_b64url(obj: Mapping[str, Any]) -> str:
    return _b64url_encode(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _consteq(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    if isinstance(a, str):
        a = a.encode()
    if isinstance(b, str):
        b = b.encode()
    return hmac.compare_digest(a, b)


def _utcnow_ts() -> int:
    return int(time.time())


# =========================
# ДАННЫЕ PRINCIPAL
# =========================

@dataclass
class Principal:
    sub: str
    tenant: Optional[str]
    roles: Set[str] = field(default_factory=set)
    scopes: Set[str] = field(default_factory=set)
    method: str = "unknown"       # jwt|hmac|api_key|mtls
    raw_claims: Dict[str, Any] = field(default_factory=dict)
    token_id: Optional[str] = None  # jti или nonce
    issuer: Optional[str] = None
    audience: Optional[Union[str, List[str]]] = None


# =========================
# ИНТЕРФЕЙСЫ ХРАНИЛИЩ
# =========================

class NonceStore:
    """Хранилище одноразовых значений (anti-replay)."""

    def add(self, key: str, ttl_seconds: int) -> bool:
        """Добавляет key с TTL. Возвращает False, если key уже существует (replay)."""
        raise NotImplementedError

    def purge(self) -> None:
        """Опционально: удалить протухшие записи."""
        return


class InMemoryNonceStore(NonceStore):
    def __init__(self, max_size: int = 100_000):
        self._data: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._max = max_size

    def add(self, key: str, ttl_seconds: int) -> bool:
        now = time.monotonic()
        exp = now + ttl_seconds
        with self._lock:
            # Сборка мусора на проходе
            if len(self._data) > self._max:
                to_del = [k for k, v in self._data.items() if v < now]
                for k in to_del[: self._max // 10 or 1]:
                    self._data.pop(k, None)
            if key in self._data and self._data[key] >= now:
                return False
            self._data[key] = exp
            return True

    def purge(self) -> None:
        now = time.monotonic()
        with self._lock:
            for k in [k for k, v in self._data.items() if v < now]:
                self._data.pop(k, None)


# =========================
# КОНФИГУРАЦИЯ
# =========================

@dataclass
class JWTConfig:
    enabled: bool = True
    algorithms: Tuple[str, ...] = ("HS256", "RS256")
    issuer: Optional[str] = None
    audience: Optional[Union[str, List[str]]] = None
    leeway_seconds: int = 60
    # HS256 секреты: либо общий, либо по kid
    hs256_secrets: Dict[str, str] = field(default_factory=dict)  # kid->secret
    hs256_default_secret: Optional[str] = None
    # RS256/JWKS
    jwks_url: Optional[str] = None
    jwks_ttl_seconds: int = 300
    require_kid: bool = False
    accept_without_exp: bool = False  # по умолчанию exp обязателен


@dataclass
class HMACConfig:
    enabled: bool = True
    secret: Optional[str] = None  # общий секрет для интеграций
    header_signature: str = "X-Signature"
    header_timestamp: str = "X-Timestamp"
    header_nonce: str = "X-Nonce"
    # Алгоритм подписи: SHA256
    max_clock_skew_seconds: int = 60
    ttl_seconds: int = 300
    nonce_store: NonceStore = field(default_factory=InMemoryNonceStore)
    include_headers: Tuple[str, ...] = ()  # опц. детерминированный список доп. заголовков в строке подписи


@dataclass
class APIKeyConfig:
    enabled: bool = True
    header_name: str = "X-API-Key"
    # Храним ключи как sha256(ключ) в hex; сравнение только по хэшу
    accepted_hashes: Set[str] = field(default_factory=set)
    # Сопоставление хэша ключа → Principal шаблон (роли/скоупы/tenant)
    keymap: Dict[str, Dict[str, Any]] = field(default_factory=dict)


@dataclass
class MTLSConfig:
    enabled: bool = True
    header_verify: str = "X-SSL-Client-Verify"
    header_dn: str = "X-SSL-Client-DN"
    header_san: str = "X-SSL-Client-SAN"
    require_verified: bool = True
    allowed_sans: Set[str] = field(default_factory=set)
    allowed_dns: Set[str] = field(default_factory=set)


@dataclass
class AuthConfig:
    jwt: JWTConfig = field(default_factory=JWTConfig)
    hmac: HMACConfig = field(default_factory=HMACConfig)
    apikey: APIKeyConfig = field(default_factory=APIKeyConfig)
    mtls: MTLSConfig = field(default_factory=MTLSConfig)

    # Глобальные правила
    allow_anonymous_paths: Tuple[str, ...] = (r"^/health$", r"^/metrics$", r"^/live$", r"^/ready$")
    excluded_methods: Tuple[str, ...] = ()  # например, ("OPTIONS",)
    # Если пусто — deny by default
    allowed_methods: Tuple[str, ...] = ("GET", "POST", "PUT", "PATCH", "DELETE")
    # Требовать авторизацию по умолчанию?
    require_auth: bool = True


# =========================
# JWKS КЭШ (минималистичный)
# =========================

class _JWKSCache:
    def __init__(self, url: str, ttl_seconds: int = 300):
        self._url = url
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._exp = 0.0
        self._jwks: Dict[str, Dict[str, Any]] = {}

    def _fetch(self) -> None:
        import urllib.request  # стандартная библиотека
        with urllib.request.urlopen(self._url, timeout=5) as r:
            body = r.read()
        data = json.loads(body)
        keys = {k["kid"]: k for k in data.get("keys", []) if "kid" in k}
        self._jwks = keys
        self._exp = time.monotonic() + self._ttl
        log.info("JWKS refreshed: %d keys", len(keys))

    def get(self, kid: str) -> Optional[Dict[str, Any]]:
        now = time.monotonic()
        with self._lock:
            if now >= self._exp:
                try:
                    self._fetch()
                except Exception as e:
                    log.warning("JWKS fetch failed: %s", e)
                    #Если кэш пуст — далее упадем на отсутствии ключа
                    self._exp = now + min(30, self._ttl)
            return self._jwks.get(kid)


# =========================
# JWT ВАЛИДАЦИЯ
# =========================

class JWTError(Exception):
    pass


def _decode_jwt_segments(token: str) -> Tuple[Dict[str, Any], Dict[str, Any], bytes]:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        raise JWTError("invalid_token_format")
    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        sig = _b64url_decode(sig_b64)
    except Exception:
        raise JWTError("invalid_token_base64")
    return header, payload, sig


def _verify_hs256(token: str, secret: str) -> Dict[str, Any]:
    header_b64, payload_b64, sig_b64 = token.split(".")
    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected = hmac.new(key=secret.encode(), msg=signing_input, digestmod=hashlib.sha256).digest()
    if not _consteq(expected, _b64url_decode(sig_b64)):
        raise JWTError("signature_invalid")
    return json.loads(_b64url_decode(payload_b64))


def _rsa_public_from_jwk(jwk: Mapping[str, str]):
    n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
    return RSAPublicNumbers(e=e, n=n).public_key()


def _verify_rs256(token: str, jwk: Mapping[str, Any]) -> Dict[str, Any]:
    if not _CRYPTO_OK:
        raise JWTError("rs256_not_supported: cryptography_missing")
    header_b64, payload_b64, sig_b64 = token.split(".")
    signing_input = f"{header_b64}.{payload_b64}".encode()
    pub = _rsa_public_from_jwk(jwk)
    try:
        pub.verify(
            _b64url_decode(sig_b64),
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception:
        raise JWTError("signature_invalid")
    return json.loads(_b64url_decode(payload_b64))


def validate_jwt(token: str, cfg: JWTConfig, jwks: Optional[_JWKSCache]) -> Dict[str, Any]:
    header, payload, _ = _decode_jwt_segments(token)
    alg = header.get("alg")
    kid = header.get("kid")

    if alg not in cfg.algorithms:
        raise JWTError("alg_not_allowed")

    if alg == "HS256":
        secret = None
        if kid and cfg.hs256_secrets:
            secret = cfg.hs256_secrets.get(kid)
        if secret is None:
            secret = cfg.hs256_default_secret
        if not secret:
            raise JWTError("hs256_secret_missing")
        claims = _verify_hs256(token, secret)
    elif alg == "RS256":
        if cfg.require_kid and not kid:
            raise JWTError("kid_required")
        if not jwks or not cfg.jwks_url:
            raise JWTError("jwks_not_configured")
        jwk = jwks.get(kid or "")
        if not jwk:
            raise JWTError("jwk_not_found")
        claims = _verify_rs256(token, jwk)
    else:
        raise JWTError("unsupported_alg")

    # Временные проверки
    now = int(time.time())
    leeway = cfg.leeway_seconds
    exp = claims.get("exp")
    if exp is None and not cfg.accept_without_exp:
        raise JWTError("exp_missing")
    if exp is not None and now > int(exp) + leeway:
        raise JWTError("token_expired")

    nbf = claims.get("nbf")
    if nbf is not None and now + leeway < int(nbf):
        raise JWTError("token_not_yet_valid")

    iat = claims.get("iat")
    if iat is not None and int(iat) - leeway > now:
        raise JWTError("invalid_iat")

    # Issuer/Audience
    if cfg.issuer and claims.get("iss") != cfg.issuer:
        raise JWTError("issuer_mismatch")

    if cfg.audience:
        aud = claims.get("aud")
        required = set(cfg.audience if isinstance(cfg.audience, list) else [cfg.audience])
        present = set(aud if isinstance(aud, list) else [aud]) if aud else set()
        if not (required & present):
            raise JWTError("audience_mismatch")

    return claims


# =========================
# HMAC ПОДПИСЬ ЗАПРОСА
# =========================

def _canonical_request(
    method: str,
    path_qs: str,
    body: bytes,
    ts: str,
    nonce: str,
    extra_headers: Iterable[Tuple[str, str]] = ()
) -> bytes:
    body_hash = hashlib.sha256(body or b"").hexdigest()
    # Включаем доп. заголовки детерминированно
    hdrs = "\n".join(f"{k.lower()}:{v.strip()}" for k, v in extra_headers)
    parts = [
        method.upper(),
        path_qs,
        body_hash,
        ts,
        nonce,
        hdrs,
    ]
    return "\n".join(parts).encode("utf-8")


def verify_hmac_request(
    request: Request, cfg: HMACConfig
) -> Principal:
    sig_hex = request.headers.get(cfg.header_signature)
    ts = request.headers.get(cfg.header_timestamp)
    nonce = request.headers.get(cfg.header_nonce)

    if not sig_hex or not ts or not nonce:
        raise PermissionError("hmac_headers_missing")

    try:
        ts_int = int(ts)
    except Exception:
        raise PermissionError("hmac_timestamp_invalid")

    now = _utcnow_ts()
    if abs(now - ts_int) > cfg.max_clock_skew_seconds:
        raise PermissionError("hmac_timestamp_skew")

    # Anti-replay
    if not cfg.nonce_store.add(nonce, cfg.ttl_seconds):
        raise PermissionError("hmac_replay_detected")

    # Собираем каноническую строку
    body = getattr(request, "_body", None)
    if body is None:
        body = (yield_body := getattr(request, "body", None))
        body = request.scope.get("_cached_body") or (request._body if hasattr(request, "_body") else None)
    # Гарантировано читаем тело один раз
    body = request.scope.get("_cached_body")
    if body is None:
        body = request._body if hasattr(request, "_body") else None
    if body is None:
        body = b""
    # Доп. заголовки
    extras = tuple((h, request.headers.get(h, "")) for h in cfg.include_headers)
    can = _canonical_request(request.method, request.url.path + ("?" + request.url.query if request.url.query else ""), body, ts, nonce, extras)

    mac = hmac.new(cfg.secret.encode(), can, hashlib.sha256).hexdigest()
    if not _consteq(mac, sig_hex.lower()):
        raise PermissionError("hmac_signature_invalid")

    return Principal(
        sub="hmac:"+request.client.host if request.client else "hmac",
        tenant=None,
        roles=set(),
        scopes=set(),
        method="hmac",
        token_id=nonce,
    )


# =========================
# API-KEY
# =========================

def verify_api_key(request: Request, cfg: APIKeyConfig) -> Principal:
    key = request.headers.get(cfg.header_name)
    if not key:
        raise PermissionError("api_key_missing")
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    if key_hash not in cfg.accepted_hashes:
        raise PermissionError("api_key_invalid")
    meta = cfg.keymap.get(key_hash, {})
    return Principal(
        sub=meta.get("sub", f"api_key:{key_hash[:8]}"),
        tenant=meta.get("tenant"),
        roles=set(meta.get("roles", [])),
        scopes=set(meta.get("scopes", [])),
        method="api_key",
    )


# =========================
# mTLS ЗА ПРОКСИ
# =========================

def verify_mtls(request: Request, cfg: MTLSConfig) -> Principal:
    if cfg.require_verified and request.headers.get(cfg.header_verify, "").lower() != "success":
        raise PermissionError("mtls_not_verified")
    san = request.headers.get(cfg.header_san, "")
    dn = request.headers.get(cfg.header_dn, "")
    # Разрешения по спискам
    ok = False
    for allowed in cfg.allowed_sans:
        if allowed and allowed in san:
            ok = True; break
    for allowed in cfg.allowed_dns:
        if allowed and allowed in dn:
            ok = True; break
    if (cfg.allowed_sans or cfg.allowed_dns) and not ok:
        raise PermissionError("mtls_subject_not_allowed")
    return Principal(
        sub=f"mtls:{san or dn or 'client'}",
        tenant=None,
        roles=set(),
        scopes=set(),
        method="mtls",
    )


# =========================
# ОСНОВНОЙ MIDDLEWARE
# =========================

class AuthMiddleware(BaseHTTPMiddleware):
    """
    Deny-by-default аутентификация с несколькими методами.
    Присваивает request.state.principal при успехе.
    """

    def __init__(self, app: ASGIApp, config: AuthConfig):
        super().__init__(app)
        self.cfg = config
        self._jwks = _JWKSCache(config.jwt.jwks_url, config.jwt.jwks_ttl_seconds) if (config.jwt.enabled and config.jwt.jwks_url) else None

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Исключения по методам/путям
        if request.method in self.cfg.excluded_methods:
            return await call_next(request)

        path = request.url.path or "/"
        for pattern in self.cfg.allow_anonymous_paths:
            if re.match(pattern, path):
                request.state.principal = None
                return await call_next(request)

        # Кандидаты
        error_chain: List[Tuple[str, str]] = []

        # 1) Bearer JWT
        if self.cfg.jwt.enabled:
            authz = request.headers.get("Authorization", "")
            if authz.startswith("Bearer "):
                token = authz[7:].strip()
                try:
                    claims = validate_jwt(token, self.cfg.jwt, self._jwks)
                    principal = Principal(
                        sub=str(claims.get("sub") or claims.get("uid") or ""),
                        tenant=claims.get("tenant") or claims.get("org") or None,
                        roles=set(_normalize_roles(claims)),
                        scopes=set(_normalize_scopes(claims)),
                        method="jwt",
                        raw_claims=claims,
                        token_id=claims.get("jti"),
                        issuer=claims.get("iss"),
                        audience=claims.get("aud"),
                    )
                    if not principal.sub:
                        raise JWTError("sub_missing")
                    request.state.principal = principal
                    _audit_ok(request, principal)
                    return await call_next(request)
                except Exception as e:
                    error_chain.append(("jwt", str(e)))

        # 2) HMAC
        if self.cfg.hmac.enabled and self.cfg.hmac.secret:
            try:
                principal = verify_hmac_request(request, self.cfg.hmac)
                request.state.principal = principal
                _audit_ok(request, principal)
                return await call_next(request)
            except Exception as e:
                error_chain.append(("hmac", str(e)))

        # 3) API-key
        if self.cfg.apikey.enabled and self.cfg.apikey.accepted_hashes:
            try:
                principal = verify_api_key(request, self.cfg.apikey)
                request.state.principal = principal
                _audit_ok(request, principal)
                return await call_next(request)
            except Exception as e:
                error_chain.append(("api_key", str(e)))

        # 4) mTLS
        if self.cfg.mtls.enabled:
            try:
                principal = verify_mtls(request, self.cfg.mtls)
                request.state.principal = principal
                _audit_ok(request, principal)
                return await call_next(request)
            except Exception as e:
                error_chain.append(("mtls", str(e)))

        # Нет валидной аутентификации
        if self.cfg.require_auth:
            _audit_deny(request, error_chain)
            return _json_error(401, "unauthorized", {"chain": error_chain})
        else:
            # Разрешаем аноним
            request.state.principal = None
            return await call_next(request)


# =========================
# RBAC ХЕЛПЕРЫ
# =========================

def _normalize_roles(claims: Mapping[str, Any]) -> List[str]:
    candidates = [
        claims.get("roles"),
        claims.get("role"),
        claims.get("realm_access", {}).get("roles"),
        claims.get("resource_access", {}).get("roles"),
    ]
    items: List[str] = []
    for c in candidates:
        if isinstance(c, list):
            items.extend([str(x) for x in c])
        elif isinstance(c, str):
            items.extend([x.strip() for x in c.split() if x.strip()])
        elif isinstance(c, dict):
            for v in c.values():
                if isinstance(v, list):
                    items.extend([str(x) for x in v])
    return sorted({x.lower() for x in items})


def _normalize_scopes(claims: Mapping[str, Any]) -> List[str]:
    c = claims.get("scope") or claims.get("scopes") or []
    items: List[str] = []
    if isinstance(c, list):
        items = [str(x) for x in c]
    elif isinstance(c, str):
        items = [x for x in c.replace(",", " ").split() if x]
    return sorted({x.lower() for x in items})


def require_scopes(*required: str):
    """FastAPI зависимость/декоратор: проверка скоупов."""
    req = {r.lower() for r in required}

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            request: Request = _extract_request(args, kwargs)
            principal: Optional[Principal] = getattr(request.state, "principal", None)
            if not principal:
                return _json_error(401, "unauthorized", {"missing": "principal"})
            if not (req <= principal.scopes):
                return _json_error(403, "forbidden", {"required_scopes": sorted(req), "have": sorted(principal.scopes)})
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def require_roles(*required: str):
    """FastAPI зависимость/декоратор: проверка ролей."""
    req = {r.lower() for r in required}

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            request: Request = _extract_request(args, kwargs)
            principal: Optional[Principal] = getattr(request.state, "principal", None)
            if not principal:
                return _json_error(401, "unauthorized", {"missing": "principal"})
            if not (req <= principal.roles):
                return _json_error(403, "forbidden", {"required_roles": sorted(req), "have": sorted(principal.roles)})
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def _extract_request(args, kwargs) -> Request:
    for a in list(args) + list(kwargs.values()):
        if isinstance(a, Request):
            return a
    # Fallback (FastAPI обычно передает Request в kwargs)
    raise RuntimeError("Request instance not found for RBAC check")


# =========================
# АУДИТ/ОТВЕТЫ
# =========================

def _json_error(code: int, err: str, details: Optional[Dict[str, Any]] = None) -> JSONResponse:
    payload = {"error": err, "details": details or {}, "ts": datetime.now(timezone.utc).isoformat()}
    return JSONResponse(payload, status_code=code)


def _audit_ok(request: Request, principal: Principal) -> None:
    extra = {
        "path": request.url.path,
        "method": request.method,
        "auth_method": principal.method,
        "sub": principal.sub,
        "tenant": principal.tenant,
        "roles": sorted(principal.roles),
        "scopes": sorted(principal.scopes),
        "client": request.client.host if request.client else None,
    }
    log.info("auth_ok %s", json.dumps(extra, ensure_ascii=False))
    if _TRACER:
        span = trace.get_current_span()
        try:
            span.set_attribute("auth.method", principal.method)
            span.set_attribute("auth.sub", principal.sub)
            if principal.tenant:
                span.set_attribute("auth.tenant", principal.tenant)
        except Exception:
            pass


def _audit_deny(request: Request, chain: List[Tuple[str, str]]) -> None:
    extra = {
        "path": request.url.path,
        "method": request.method,
        "reasons": chain,
        "client": request.client.host if request.client else None,
    }
    log.warning("auth_deny %s", json.dumps(extra, ensure_ascii=False))
    if _TRACER:
        span = trace.get_current_span()
        try:
            span.set_attribute("auth.denied", True)
            span.set_attribute("auth.reasons", str(chain))
        except Exception:
            pass


# =========================
# БЫСТРОЕ ВКЛЮЧЕНИЕ В FASTAPI
# =========================
# Пример:
#   app.add_middleware(AuthMiddleware, config=AuthConfig(
#       jwt=JWTConfig(issuer="https://issuer", audience=["api"], jwks_url="https://issuer/.well-known/jwks.json"),
#       hmac=HMACConfig(secret="supersecret"),
#       apikey=APIKeyConfig(accepted_hashes={"<sha256hex>"}, keymap={"<sha256hex>": {"roles":["admin"],"scopes":["root"]}}),
#       mtls=MTLSConfig(allowed_sans={"spiffe://oblivionvault/workload"})
#   ))
#
#   @app.get("/protected")
#   @require_scopes("read:items")
#   async def protected(request: Request): ...


__all__ = [
    "AuthMiddleware",
    "AuthConfig",
    "JWTConfig",
    "HMACConfig",
    "APIKeyConfig",
    "MTLSConfig",
    "Principal",
    "require_scopes",
    "require_roles",
    "InMemoryNonceStore",
    "NonceStore",
]
