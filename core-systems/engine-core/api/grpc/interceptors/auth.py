from __future__ import annotations

import asyncio
import contextvars
import hashlib
import hmac
import json
import os
import re
import ssl
import time
import typing as t
from dataclasses import dataclass, field

import grpc
from grpc import StatusCode
from grpc.aio import ServerInterceptor, ServicerContext
from jwt import PyJWTError, decode as jwt_decode, algorithms  # pip install PyJWT

# =========================
# Конфигурация из окружения
# =========================

AUTH_ALLOW_ANON = os.getenv("AUTH_ALLOW_ANON", "false").lower() == "true"

# JWT
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "")
JWT_ISSUER = os.getenv("JWT_ISSUER", "")
JWT_ALGS = tuple(
    alg.strip()
    for alg in os.getenv("JWT_ALGS", "RS256,ES256").split(",")
    if alg.strip()
)
JWT_LEEWAY_SEC = int(os.getenv("JWT_LEEWAY_SEC", "30"))
JWT_JWKS_URL = os.getenv("JWT_JWKS_URL", "")  # если задан — используется JWKS
JWT_STATIC_PUBKEY = os.getenv("JWT_STATIC_PUBKEY", "")  # PEM строка на случай отсутствия JWKS
JWT_CACHE_TTL_SEC = int(os.getenv("JWT_CACHE_TTL_SEC", "600"))
JWT_HTTP_TIMEOUT_SEC = float(os.getenv("JWT_HTTP_TIMEOUT_SEC", "2.0"))

# API-KEY (поддержка нескольких ключей, разделённых запятыми; допускается формат id:secret)
API_KEYS = [k for k in os.getenv("API_KEYS", "").split(",") if k.strip()]
API_KEY_HEADER = os.getenv("API_KEY_HEADER", "x-api-key").lower()

# mTLS / SPIFFE
MTLS_REQUIRE = os.getenv("MTLS_REQUIRE", "false").lower() == "true"
MTLS_ALLOWED_SPIFFE_RE = os.getenv("MTLS_ALLOWED_SPIFFE_RE", "")  # ^spiffe://trust-domain/service/.+
MTLS_ALLOWED_SAN_RE = os.getenv("MTLS_ALLOWED_SAN_RE", "")        # ^svc-[a-z0-9\-]+\.prod\.cluster\.local$
MTLS_ALLOWED_CN_RE = os.getenv("MTLS_ALLOWED_CN_RE", "")          # ^service-[a-z0-9\-]+$

# RBAC: JSON‑карта "{ 'package.Service/Method': ['scope:a','role:b'] , 'package.Service/*': ['scope:x'] }"
RBAC_POLICY_JSON = os.getenv("GRPC_RBAC_POLICY_JSON", "{}")

# Общее
REQUEST_ID_HEADER = os.getenv("REQUEST_ID_HEADER", "x-request-id").lower()

# =========================
# Утилиты
# =========================

_json_policy: dict[str, list[str]] | None = None
def _load_rbac_policy() -> dict[str, list[str]]:
    global _json_policy
    if _json_policy is None:
        try:
            _json_policy = json.loads(RBAC_POLICY_JSON or "{}")
        except json.JSONDecodeError:
            _json_policy = {}
    return _json_policy

def _const_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())

def _method_to_key(method: str) -> tuple[str, str]:
    # :method выглядит как "/package.Service/Method"
    if not method.startswith("/"):
        return "", ""
    parts = method[1:].split("/", 1)
    if len(parts) != 2:
        return "", ""
    return parts[0], parts[1]  # "package.Service", "Method"

def _match_rbac(method: str, scopes: set[str], roles: set[str]) -> bool:
    svc, mth = _method_to_key(method)
    if not svc:
        return False
    pol = _load_rbac_policy()
    required: list[str] = []
    # Точные и подстановочные правила
    for key in (f"{svc}/{mth}", f"{svc}/*", f"*/{mth}", "*/*"):
        if key in pol:
            required.extend(pol[key])
    if not required:
        # Если политика не определена, по умолчанию запрещаем (fail closed)
        return False

    need_scopes = {r.split(":", 1)[1] for r in required if r.startswith("scope:")}
    need_roles = {r.split(":", 1)[1] for r in required if r.startswith("role:")}

    if need_scopes and not (need_scopes & scopes):
        return False
    if need_roles and not (need_roles & roles):
        return False
    return True

def _parse_auth_header(md: tuple[tuple[str, str], ...]) -> str | None:
    for k, v in md:
        if k.lower() == "authorization":
            if v.lower().startswith("bearer "):
                return v[7:].strip()
    return None

def _get_md_value(md: tuple[tuple[str, str], ...], name: str) -> str | None:
    lname = name.lower()
    for k, v in md:
        if k.lower() == lname:
            return v
    return None

def _extract_peer_auth_context(ctx: ServicerContext) -> dict[str, list[bytes]]:
    try:
        return ctx.auth_context()
    except Exception:
        return {}

# =========================
# JWKS кэш и загрузка
# =========================

@dataclass
class _JwksCache:
    keys_by_kid: dict[str, dict] = field(default_factory=dict)
    expires_at: float = 0.0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

_jwks_cache = _JwksCache()

async def _fetch_jwks(url: str, timeout: float) -> dict:
    # Без внешних зависимостей: используем grpc.aio для простой выборки нельзя;
    # поэтому разрешим aiohttp при наличии, иначе — пусто.
    try:
        import aiohttp  # type: ignore
    except Exception:
        return {}
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as s:
        async with s.get(url) as r:
            if r.status != 200:
                return {}
            return await r.json()

async def _get_jwt_key(token_headers: dict) -> t.Any:
    if JWT_JWKS_URL:
        now = time.time()
        async with _jwks_cache.lock:
            if now >= _jwks_cache.expires_at:
                jwks = await _fetch_jwks(JWT_JWKS_URL, JWT_HTTP_TIMEOUT_SEC)
                keys = {}
                for k in jwks.get("keys", []):
                    kid = k.get("kid")
                    if not kid:
                        continue
                    keys[kid] = k
                _jwks_cache.keys_by_kid = keys
                _jwks_cache.expires_at = now + JWT_CACHE_TTL_SEC
            kid = token_headers.get("kid")
            if kid and kid in _jwks_cache.keys_by_kid:
                jwk = _jwks_cache.keys_by_kid[kid]
                return algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk)) if jwk.get("kty") == "RSA" else algorithms.ECAlgorithm.from_jwk(json.dumps(jwk))
            # если нет kid — попробуем все ключи
            for jwk in _jwks_cache.keys_by_kid.values():
                try:
                    if jwk.get("kty") == "RSA":
                        return algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
                    if jwk.get("kty") == "EC":
                        return algorithms.ECAlgorithm.from_jwk(json.dumps(jwk))
                except Exception:
                    continue
    if JWT_STATIC_PUBKEY:
        return JWT_STATIC_PUBKEY
    return None

# =========================
# Результаты аутентификации
# =========================

@dataclass
class Principal:
    subject: str
    source: str               # "jwt"|"mtls"|"apikey"|"anon"
    scopes: set[str] = field(default_factory=set)
    roles: set[str] = field(default_factory=set)
    claims: dict = field(default_factory=dict)
    peer: str | None = None
    request_id: str | None = None

principal_ctx: contextvars.ContextVar[Principal | None] = contextvars.ContextVar("principal_ctx", default=None)

# =========================
# Валидаторы
# =========================

async def _validate_api_key(md: tuple[tuple[str, str], ...]) -> Principal | None:
    if not API_KEYS:
        return None
    key = _get_md_value(md, API_KEY_HEADER)
    if not key:
        return None
    for k in API_KEYS:
        if ":" in k:
            _, secret = k.split(":", 1)
            if _const_time_eq(key, secret):
                return Principal(subject="apikey:"+hashlib.sha256(secret.encode()).hexdigest()[:16], source="apikey")
        else:
            if _const_time_eq(key, k):
                return Principal(subject="apikey:"+hashlib.sha256(k.encode()).hexdigest()[:16], source="apikey")
    return None

async def _validate_jwt(md: tuple[tuple[str, str], ...]) -> Principal | None:
    token = _parse_auth_header(md)
    if not token:
        return None
    try:
        unverified_header = algorithms.get_unverified_header(token)
    except PyJWTError:
        return None
    key = await _get_jwt_key(unverified_header)
    if not key:
        # Нет ключа — откажем молча
        return None
    options = {
        "verify_aud": bool(JWT_AUDIENCE),
        "verify_signature": True,
        "verify_exp": True,
        "verify_nbf": True,
        "verify_iat": True,
        "require": ["exp", "iat"],
    }
    try:
        claims = jwt_decode(
            token,
            key=key,
            algorithms=list(JWT_ALGS) if JWT_ALGS else None,
            audience=JWT_AUDIENCE or None,
            issuer=JWT_ISSUER or None,
            leeway=JWT_LEEWAY_SEC,
            options=options,
        )
    except PyJWTError:
        return None

    sub = str(claims.get("sub") or claims.get("client_id") or "unknown")
    scopes = set()
    for field in ("scope", "scopes"):
        v = claims.get(field)
        if isinstance(v, str):
            scopes |= set(s for s in v.replace(",", " ").split() if s)
        elif isinstance(v, (list, tuple)):
            scopes |= {str(s) for s in v}
    roles = set()
    for field in ("roles", "role"):
        v = claims.get(field)
        if isinstance(v, str):
            roles |= set(s for s in v.replace(",", " ").split() if s)
        elif isinstance(v, (list, tuple)):
            roles |= {str(s) for s in v}

    return Principal(subject=sub, source="jwt", scopes=scopes, roles=roles, claims=claims)

async def _validate_mtls(ctx: ServicerContext) -> Principal | None:
    if not MTLS_REQUIRE and not (MTLS_ALLOWED_SPIFFE_RE or MTLS_ALLOWED_SAN_RE or MTLS_ALLOWED_CN_RE):
        return None
    authc = _extract_peer_auth_context(ctx)
    # gRPC передаёт сертификат через 'x509_common_name', 'x509_subject_alternative_name'
    cns = [v.decode() for v in authc.get("x509_common_name", [])]
    sans = [v.decode() for v in authc.get("x509_subject_alternative_name", [])]
    spiffe_ids = [v.decode() for v in authc.get("spiffe_id", [])]  # зависит от прокси/sidecar

    def _match_any(values: list[str], pattern: str) -> bool:
        if not pattern:
            return False
        rx = re.compile(pattern)
        return any(rx.match(x) for x in values)

    ok = False
    if MTLS_ALLOWED_SPIFFE_RE and _match_any(spiffe_ids, MTLS_ALLOWED_SPIFFE_RE):
        ok = True
    if MTLS_ALLOWED_SAN_RE and _match_any(sans, MTLS_ALLOWED_SAN_RE):
        ok = True
    if MTLS_ALLOWED_CN_RE and _match_any(cns, MTLS_ALLOWED_CN_RE):
        ok = True

    if MTLS_REQUIRE and not ok:
        # Явно требуется — но не совпало
        return None

    if ok:
        ident = spiffe_ids[0] if spiffe_ids else (sans[0] if sans else (cns[0] if cns else "mtls"))
        return Principal(subject=ident, source="mtls", claims={"cns": cns, "sans": sans, "spiffe": spiffe_ids})
    return None

# =========================
# Основной интерсептор
# =========================

class AuthInterceptor(ServerInterceptor):
    """
    Порядок:
      1) Вытянуть request-id
      2) Попытки mTLS, JWT, API-Key
      3) Если все мимо — отказ (если не включён AUTH_ALLOW_ANON)
      4) RBAC для метода
      5) Прокинуть Principal в contextvar и context.invocation_metadata()
    """

    def __init__(self) -> None:
        self._rbac_policy = _load_rbac_policy()

    async def intercept_service(
        self,
        continuation: t.Callable[[grpc.HandlerCallDetails], t.Awaitable[grpc.RpcMethodHandler]],
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler:

        method = handler_call_details.method
        metadata: tuple[tuple[str, str], ...] = handler_call_details.invocation_metadata or ()

        async def _unauth(code: StatusCode, ctx: ServicerContext, msg: str) -> None:
            # Не раскрываем детали
            await ctx.abort(code, msg)

        async def _auth_and_wrap(handler: grpc.RpcMethodHandler) -> grpc.RpcMethodHandler:
            # 1) request-id
            req_id = _get_md_value(metadata, REQUEST_ID_HEADER) or _get_md_value(metadata, "x-request-id")
            # 2) источники
            principal: Principal | None = None

            async def try_mtls(ctx: ServicerContext) -> Principal | None:
                return await _validate_mtls(ctx)

            async def try_jwt() -> Principal | None:
                return await _validate_jwt(metadata)

            async def try_apikey() -> Principal | None:
                return await _validate_api_key(metadata)

            # Проверять mTLS нужно уже имея ServicerContext, поэтому сделаем ленивую проверку внутри каждого вида RPC.

            # Обёртки для каждого типа RPC:
            if handler.unary_unary:
                inner = handler.unary_unary

                async def uu(request, ctx: ServicerContext):
                    nonlocal principal
                    if req_id:
                        ctx.set_trailing_metadata(((REQUEST_ID_HEADER, req_id),))
                    # mTLS
                    principal = principal or await try_mtls(ctx)
                    # JWT
                    principal = principal or await try_jwt()
                    # API-Key
                    principal = principal or await try_apikey()

                    if not principal and not AUTH_ALLOW_ANON:
                        return await _unauth(StatusCode.UNAUTHENTICATED, ctx, "unauthenticated")

                    if principal:
                        principal.request_id = req_id
                        principal.peer = ctx.peer()
                        # RBAC
                        if not _match_rbac(method, principal.scopes, principal.roles):
                            return await _unauth(StatusCode.PERMISSION_DENIED, ctx, "permission denied")
                    # Прокидываем principal через contextvar
                    token = principal_ctx.set(principal)
                    try:
                        return await inner(request, ctx)
                    finally:
                        principal_ctx.reset(token)

                return grpc.unary_unary_rpc_method_handler(
                    uu,
                    request_deserializer=handler.request_deserializer,
                    response_serializer=handler.response_serializer,
                )

            if handler.unary_stream:
                inner = handler.unary_stream

                async def us(request, ctx: ServicerContext):
                    nonlocal principal
                    if req_id:
                        ctx.set_trailing_metadata(((REQUEST_ID_HEADER, req_id),))
                    principal = principal or await try_mtls(ctx)
                    principal = principal or await try_jwt()
                    principal = principal or await try_apikey()
                    if not principal and not AUTH_ALLOW_ANON:
                        return await _unauth(StatusCode.UNAUTHENTICATED, ctx, "unauthenticated")
                    if principal and not _match_rbac(method, principal.scopes, principal.roles):
                        return await _unauth(StatusCode.PERMISSION_DENIED, ctx, "permission denied")
                    token = principal_ctx.set(principal)
                    try:
                        async for resp in inner(request, ctx):
                            yield resp
                    finally:
                        principal_ctx.reset(token)

                return grpc.unary_stream_rpc_method_handler(
                    us,
                    request_deserializer=handler.request_deserializer,
                    response_serializer=handler.response_serializer,
                )

            if handler.stream_unary:
                inner = handler.stream_unary

                async def su(request_iter, ctx: ServicerContext):
                    nonlocal principal
                    if req_id:
                        ctx.set_trailing_metadata(((REQUEST_ID_HEADER, req_id),))
                    principal = principal or await try_mtls(ctx)
                    principal = principal or await try_jwt()
                    principal = principal or await try_apikey()
                    if not principal and not AUTH_ALLOW_ANON:
                        return await _unauth(StatusCode.UNAUTHENTICATED, ctx, "unauthenticated")
                    if principal and not _match_rbac(method, principal.scopes, principal.roles):
                        return await _unauth(StatusCode.PERMISSION_DENIED, ctx, "permission denied")
                    token = principal_ctx.set(principal)
                    try:
                        return await inner(request_iter, ctx)
                    finally:
                        principal_ctx.reset(token)

                return grpc.stream_unary_rpc_method_handler(
                    su,
                    request_deserializer=handler.request_deserializer,
                    response_serializer=handler.response_serializer,
                )

            if handler.stream_stream:
                inner = handler.stream_stream

                async def ss(request_iter, ctx: ServicerContext):
                    nonlocal principal
                    if req_id:
                        ctx.set_trailing_metadata(((REQUEST_ID_HEADER, req_id),))
                    principal = principal or await try_mtls(ctx)
                    principal = principal or await try_jwt()
                    principal = principal or await try_apikey()
                    if not principal and not AUTH_ALLOW_ANON:
                        return await _unauth(StatusCode.UNAUTHENTICATED, ctx, "unauthenticated")
                    if principal and not _match_rbac(method, principal.scopes, principal.roles):
                        return await _unauth(StatusCode.PERMISSION_DENIED, ctx, "permission denied")
                    token = principal_ctx.set(principal)
                    try:
                        async for resp in inner(request_iter, ctx):
                            yield resp
                    finally:
                        principal_ctx.reset(token)

                return grpc.stream_stream_rpc_method_handler(
                    ss,
                    request_deserializer=handler.request_deserializer,
                    response_serializer=handler.response_serializer,
                )

            # На всякий случай: неизвестный тип обработчика
            return handler

        handler = await continuation(handler_call_details)
        return await _auth_and_wrap(handler)

# =========================
# Хелперы для бизнес-кода
# =========================

def current_principal() -> Principal | None:
    """Получить Principal внутри сервиса/хэндлера."""
    return principal_ctx.get()

def require_scope(scope: str) -> None:
    p = current_principal()
    if not p or scope not in (p.scopes or set()):
        # Используем обычное исключение — его перехватит бизнес‑код и превратит в gRPC ошибку
        raise PermissionError("missing required scope")

def require_role(role: str) -> None:
    p = current_principal()
    if not p or role not in (p.roles or set()):
        raise PermissionError("missing required role")

# =========================
# Пример инициализации сервера
# =========================
# from grpc.aio import server
# s = server(interceptors=[AuthInterceptor()])
# ... add Servicers ...
# s.add_insecure_port("0.0.0.0:50051") or use TLS with credentials

