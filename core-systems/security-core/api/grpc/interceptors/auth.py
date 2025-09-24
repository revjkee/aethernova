# security-core/api/grpc/interceptors/auth.py
# Промышленный gRPC интерсептор аутентификации/авторизации (Zero-Trust, multi-tenant)
# Зависимости: grpcio (и/или grpcio-status), опционально PyJWT, cryptography
from __future__ import annotations

import base64
import binascii
import contextvars
import hashlib
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import grpc

try:
    # Опционально: точные коды статусов и детали
    from grpc_status import rpc_status  # noqa: F401
except Exception:  # noqa: BLE001
    rpc_status = None

try:
    import jwt  # PyJWT
except Exception:  # noqa: BLE001
    jwt = None

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.hazmat.primitives.serialization import PublicFormat
except Exception:  # noqa: BLE001
    x509 = None  # type: ignore

logger = logging.getLogger(os.getenv("SERVICE_NAME", "security-core.grpc.auth"))
logger.setLevel(getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO))

# ------------------------------------------------------------------------------
# Context Principal (доступен внутри обработчиков сервисов через get_current_principal)
# ------------------------------------------------------------------------------

_principal_ctx: contextvars.ContextVar["Principal"] = contextvars.ContextVar("principal", default=None)  # type: ignore


@dataclass(frozen=True)
class Principal:
    subject: str = "anonymous"
    tenant: Optional[str] = None
    scopes: Tuple[str, ...] = field(default_factory=tuple)
    token_id: Optional[str] = None  # jti
    issued_at: Optional[int] = None  # iat (epoch)
    expires_at: Optional[int] = None  # exp (epoch)
    auth_time: Optional[int] = None  # auth_time (epoch)
    claims: Mapping[str, Any] = field(default_factory=dict)
    peer_cn: Optional[str] = None
    cert_fingerprint: Optional[str] = None  # SHA256 hex
    method: Optional[str] = None  # полное имя RPC-метода


def get_current_principal() -> Optional[Principal]:
    """Получить Principal текущего RPC из contextvars (или None)."""
    try:
        return _principal_ctx.get()
    except Exception:  # noqa: BLE001
        return None


# ------------------------------------------------------------------------------
# Конфигурация и провайдер ключей
# ------------------------------------------------------------------------------

class KeyProvider:
    """Абстракция провайдера ключей для верификации JWT (поддержка ротации, KID)."""

    def get_key(self, kid: Optional[str]) -> Tuple[str, Optional[str]]:
        """
        Вернуть (key, algorithm) для подписи.
        algorithm может быть None — тогда выбирается из конфигурации.
        """
        raise NotImplementedError


class HMACKeyProvider(KeyProvider):
    """Простой HMAC-провайдер: один общий секрет или мапа kid->секрет."""

    def __init__(self, default_secret: str, by_kid: Optional[Mapping[str, str]] = None) -> None:
        self._default = default_secret
        self._by_kid = dict(by_kid or {})

    def get_key(self, kid: Optional[str]) -> Tuple[str, Optional[str]]:
        if kid and kid in self._by_kid:
            return self._by_kid[kid], None
        return self._default, None


@dataclass
class AuthConfig:
    allow_anonymous: bool = False
    jwt_enabled: bool = True
    required_scopes_by_method: Mapping[str, Sequence[str]] = field(default_factory=dict)  # "/package.Service/Method": ["scope:a", ...]
    public_methods: Sequence[str] = field(default_factory=tuple)  # методы, не требующие аутентификации
    issuer: Optional[str] = None
    audience: Optional[str] = None
    leeway_seconds: int = 30
    algorithms: Sequence[str] = ("HS256", "HS384", "HS512")  # при HMAC по умолчанию
    tenant_header: str = "x-tenant-id"
    request_id_header: str = "x-request-id"
    accept_metadata_tenant_only: bool = False  # если True — запрещать tenant из токена
    enforce_tenant_match: bool = True  # сверять header vs claim
    # Дополнительно: произвольная проверка claims/метаданных/mtls
    claims_validator: Optional[Callable[[Mapping[str, Any], Mapping[str, str]], None]] = None
    # Кей‑провайдер (обязателен при jwt_enabled)
    key_provider: Optional[KeyProvider] = None


# ------------------------------------------------------------------------------
# Утилиты: обработка метаданных, JWT, mTLS
# ------------------------------------------------------------------------------

_AUTH_RE = re.compile(r"^\s*Bearer\s+(.+)\s*$", re.IGNORECASE)


def _metadata_to_dict(md: Optional[Sequence[Tuple[str, str]]]) -> Dict[str, str]:
    res: Dict[str, str] = {}
    if not md:
        return res
    for k, v in md:
        lk = k.lower()
        # берём первое значение ключа (для gRPC обычно одна пара)
        if lk not in res:
            res[lk] = v
    return res


def _extract_bearer_token(md: Mapping[str, str]) -> Optional[str]:
    auth = md.get("authorization")
    if not auth:
        return None
    m = _AUTH_RE.match(auth)
    return m.group(1) if m else None


def _epoch_now() -> int:
    return int(time.time())


def _jwt_decode(token: str, cfg: AuthConfig) -> Mapping[str, Any]:
    if not jwt:
        raise grpc.RpcError(grpc.StatusCode.UNAUTHENTICATED, "JWT library not available")
    # Декодировать заголовок для KID
    try:
        header = jwt.get_unverified_header(token)
    except Exception as e:  # noqa: BLE001
        _raise_unauthed(f"malformed jwt header: {e}")
    kid = header.get("kid")
    if not cfg.key_provider:
        _raise_unauthed("no key provider configured")

    key, algo_override = cfg.key_provider.get_key(kid)
    algorithms = [algo_override] if algo_override else list(cfg.algorithms)

    options = {"verify_aud": bool(cfg.audience)}
    try:
        payload = jwt.decode(
            token,
            key,
            algorithms=algorithms,
            audience=cfg.audience if cfg.audience else None,
            issuer=cfg.issuer if cfg.issuer else None,
            leeway=cfg.leeway_seconds,
            options=options,
        )
        return payload
    except Exception as e:  # noqa: BLE001
        _raise_unauthed(f"jwt verification failed: {e}")
    return {}  # недостижимо


def _parse_mtls(context: grpc.ServicerContext) -> Tuple[Optional[str], Optional[str]]:
    """
    Извлечь CN и SHA256 отпечаток клиентского сертификата из контекста.
    Работает при включенном mTLS (gRPC auth_context содержит атрибуты x509).
    """
    try:
        ac = context.auth_context()
    except Exception:
        return None, None
    # Ключи auth_context — bytes
    cn = None
    fingerprint = None
    try:
        # Некоторые окружения передают CN как "x509_common_name"
        for k, v in ac.items():
            if k == b"x509_common_name" and v and isinstance(v, (list, tuple)):
                cn = v[0].decode("utf-8", "ignore")
        # Пытаемся извлечь весь PEM сертификат
        pem_list = ac.get(b"x509_pem_cert")
        if x509 and pem_list:
            pem = pem_list[0]
            cert = x509.load_pem_x509_certificate(pem)
            fp = cert.fingerprint(hashes.SHA256())
            fingerprint = binascii.hexlify(fp).decode("ascii")
            if not cn:
                subj = cert.subject.rfc4514_string()
                # Пробуем выдернуть CN из subject
                for rdn in subj.split(","):
                    if rdn.strip().startswith("CN="):
                        cn = rdn.strip()[3:]
                        break
    except Exception:
        # Игнор — mTLS не обязателен
        pass
    return cn, fingerprint


def _mask(s: Optional[str], head: int = 3, tail: int = 3) -> Optional[str]:
    if not s:
        return s
    if len(s) <= head + tail:
        return "*" * len(s)
    return s[:head] + "*" * (len(s) - head - tail) + s[-tail:]


def _raise_unauthed(message: str) -> None:
    logger.debug("UNAUTHENTICATED: %s", message)
    context = grpc.ServicerContext  # только для type-hints
    # Поднимаем исключение с соответствующим статусом
    raise grpc.RpcError(grpc.StatusCode.UNAUTHENTICATED, message)


def _raise_forbidden(message: str) -> None:
    logger.debug("PERMISSION_DENIED: %s", message)
    raise grpc.RpcError(grpc.StatusCode.PERMISSION_DENIED, message)


def _build_principal(
    claims: Mapping[str, Any],
    md: Mapping[str, str],
    method: str,
    mtls_cn: Optional[str],
    mtls_fp: Optional[str],
    cfg: AuthConfig,
) -> Principal:
    sub = str(claims.get("sub") or "unknown")
    tid = md.get(cfg.tenant_header.lower())
    claim_tenant = None if cfg.accept_metadata_tenant_only else (claims.get("tenant") or claims.get("tid"))
    tenant = (tid or claim_tenant) if (tid or claim_tenant) else None

    if cfg.enforce_tenant_match and tid and claim_tenant and str(tid) != str(claim_tenant):
        _raise_forbidden("tenant mismatch between header and token")

    scopes: Tuple[str, ...] = tuple(
        (claims.get("scope", "") or "").split()
        if isinstance(claims.get("scope"), str)
        else (claims.get("scopes") or [])
    )

    jti = claims.get("jti")
    iat = claims.get("iat")
    exp = claims.get("exp")
    auth_time = claims.get("auth_time")

    return Principal(
        subject=sub,
        tenant=str(tenant) if tenant else None,
        scopes=tuple(map(str, scopes)) if scopes else tuple(),
        token_id=str(jti) if jti else None,
        issued_at=int(iat) if iat else None,
        expires_at=int(exp) if exp else None,
        auth_time=int(auth_time) if auth_time else None,
        claims=claims,
        peer_cn=mtls_cn,
        cert_fingerprint=mtls_fp,
        method=method,
    )


def _check_required_scopes(pr: Principal, method: str, cfg: AuthConfig) -> None:
    req = cfg.required_scopes_by_method.get(method) or ()
    if not req:
        return
    have = set(pr.scopes or ())
    need = set(req)
    missing = [s for s in need if s not in have]
    if missing:
        _raise_forbidden(f"missing scopes: {', '.join(missing)}")


# ------------------------------------------------------------------------------
# Обёртки обработчиков RPC (unary/stream)
# ------------------------------------------------------------------------------

def _wrap_unary_unary(behavior, cfg: AuthConfig):
    def handler(request, context: grpc.ServicerContext):
        method = context._rpc_event.call_details.method  # type: ignore[attr-defined]
        md = _metadata_to_dict(context.invocation_metadata())
        if method in cfg.public_methods:
            token = _extract_bearer_token(md)
            principal = Principal(subject="anonymous", tenant=md.get(cfg.tenant_header.lower()), method=method)
            if token and jwt:
                try:
                    claims = jwt.decode(token, options={"verify_signature": False})  # только для трассировки
                    principal = Principal(subject=str(claims.get("sub") or "anonymous"), tenant=principal.tenant, method=method, claims=claims)
                except Exception:
                    pass
            token = None  # для GC
            token_ctx = _principal_ctx.set(principal)
            try:
                return behavior(request, context)
            finally:
                _principal_ctx.reset(token_ctx)

        token = _extract_bearer_token(md)
        cn, fp = _parse_mtls(context)

        if not token:
            if cfg.allow_anonymous and not cfg.jwt_enabled:
                principal = Principal(subject="anonymous", tenant=md.get(cfg.tenant_header.lower()), method=method, peer_cn=cn, cert_fingerprint=fp)
            else:
                _raise_unauthed("missing bearer token")
        else:
            claims = _jwt_decode(token, cfg) if cfg.jwt_enabled else {}
            if cfg.claims_validator:
                cfg.claims_validator(claims, md)
            principal = _build_principal(claims, md, method, cn, fp, cfg)

        # Скоупы
        _check_required_scopes(principal, method, cfg)

        # Контекст
        token_ctx = _principal_ctx.set(principal)
        try:
            return behavior(request, context)
        finally:
            _principal_ctx.reset(token_ctx)
    return handler


def _wrap_unary_stream(behavior, cfg: AuthConfig):
    def handler(request, context: grpc.ServicerContext):
        method = context._rpc_event.call_details.method  # type: ignore[attr-defined]
        md = _metadata_to_dict(context.invocation_metadata())
        token = _extract_bearer_token(md)
        cn, fp = _parse_mtls(context)

        if method in cfg.public_methods:
            principal = Principal(subject="anonymous", tenant=md.get(cfg.tenant_header.lower()), method=method)
        else:
            if not token and not (cfg.allow_anonymous and not cfg.jwt_enabled):
                _raise_unauthed("missing bearer token")
            claims = _jwt_decode(token, cfg) if (token and cfg.jwt_enabled) else {}
            if cfg.claims_validator:
                cfg.claims_validator(claims, md)
            principal = _build_principal(claims, md, method, cn, fp, cfg)
            _check_required_scopes(principal, method, cfg)

        token_ctx = _principal_ctx.set(principal)
        try:
            for resp in behavior(request, context):
                yield resp
        finally:
            _principal_ctx.reset(token_ctx)
    return handler


def _wrap_stream_unary(behavior, cfg: AuthConfig):
    def handler(request_iterator, context: grpc.ServicerContext):
        method = context._rpc_event.call_details.method  # type: ignore[attr-defined]
        md = _metadata_to_dict(context.invocation_metadata())
        token = _extract_bearer_token(md)
        cn, fp = _parse_mtls(context)

        if method in cfg.public_methods:
            principal = Principal(subject="anonymous", tenant=md.get(cfg.tenant_header.lower()), method=method)
        else:
            if not token and not (cfg.allow_anonymous and not cfg.jwt_enabled):
                _raise_unauthed("missing bearer token")
            claims = _jwt_decode(token, cfg) if (token and cfg.jwt_enabled) else {}
            if cfg.claims_validator:
                cfg.claims_validator(claims, md)
            principal = _build_principal(claims, md, method, cn, fp, cfg)
            _check_required_scopes(principal, method, cfg)

        token_ctx = _principal_ctx.set(principal)
        try:
            return behavior(request_iterator, context)
        finally:
            _principal_ctx.reset(token_ctx)
    return handler


def _wrap_stream_stream(behavior, cfg: AuthConfig):
    def handler(request_iterator, context: grpc.ServicerContext):
        method = context._rpc_event.call_details.method  # type: ignore[attr-defined]
        md = _metadata_to_dict(context.invocation_metadata())
        token = _extract_bearer_token(md)
        cn, fp = _parse_mtls(context)

        if method in cfg.public_methods:
            principal = Principal(subject="anonymous", tenant=md.get(cfg.tenant_header.lower()), method=method)
        else:
            if not token and not (cfg.allow_anonymous and not cfg.jwt_enabled):
                _raise_unauthed("missing bearer token")
            claims = _jwt_decode(token, cfg) if (token and cfg.jwt_enabled) else {}
            if cfg.claims_validator:
                cfg.claims_validator(claims, md)
            principal = _build_principal(claims, md, method, cn, fp, cfg)
            _check_required_scopes(principal, method, cfg)

        token_ctx = _principal_ctx.set(principal)
        try:
            for resp in behavior(request_iterator, context):
                yield resp
        finally:
            _principal_ctx.reset(token_ctx)
    return handler


# ------------------------------------------------------------------------------
# Интерсепторы: sync и async
# ------------------------------------------------------------------------------

class AuthInterceptor(grpc.ServerInterceptor):
    """Синхронный gRPC интерсептор (grpc.Server)."""

    def __init__(self, config: AuthConfig) -> None:
        self._cfg = config

    def intercept_service(self, continuation, handler_call_details):
        handler = continuation(handler_call_details)
        if handler is None:
            return None

        # Оборачиваем все типы RPC
        if handler.unary_unary:
            return grpc.unary_unary_rpc_method_handler(
                _wrap_unary_unary(handler.unary_unary, self._cfg),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.unary_stream:
            return grpc.unary_stream_rpc_method_handler(
                _wrap_unary_stream(handler.unary_stream, self._cfg),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.stream_unary:
            return grpc.stream_unary_rpc_method_handler(
                _wrap_stream_unary(handler.stream_unary, self._cfg),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.stream_stream:
            return grpc.stream_stream_rpc_method_handler(
                _wrap_stream_stream(handler.stream_stream, self._cfg),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        return handler


# ---------- ASYNC (grpc.aio) ----------

try:
    from grpc import aio
except Exception:  # noqa: BLE001
    aio = None  # type: ignore


if aio:

    async def _awrap_unary_unary(behavior, cfg: AuthConfig):
        async def handler(request, context: aio.ServicerContext):
            method = context._rpc_event.call_details.method  # type: ignore[attr-defined]
            md = _metadata_to_dict(await context.invocation_metadata())  # type: ignore[func-returns-value]
            if method in cfg.public_methods:
                principal = Principal(subject="anonymous", tenant=md.get(cfg.tenant_header.lower()), method=method)
                token_ctx = _principal_ctx.set(principal)
                try:
                    return await behavior(request, context)
                finally:
                    _principal_ctx.reset(token_ctx)

            token = _extract_bearer_token(md)
            cn, fp = _parse_mtls(context)

            if not token and not (cfg.allow_anonymous and not cfg.jwt_enabled):
                _raise_unauthed("missing bearer token")

            claims = _jwt_decode(token, cfg) if (token and cfg.jwt_enabled) else {}
            if cfg.claims_validator:
                cfg.claims_validator(claims, md)
            principal = _build_principal(claims, md, method, cn, fp, cfg)
            _check_required_scopes(principal, method, cfg)

            token_ctx = _principal_ctx.set(principal)
            try:
                return await behavior(request, context)
            finally:
                _principal_ctx.reset(token_ctx)
        return handler

    async def _awrap_unary_stream(behavior, cfg: AuthConfig):
        async def handler(request, context: aio.ServicerContext):
            method = context._rpc_event.call_details.method  # type: ignore[attr-defined]
            md = _metadata_to_dict(await context.invocation_metadata())  # type: ignore[func-returns-value]
            token = _extract_bearer_token(md)
            cn, fp = _parse_mtls(context)

            if method in cfg.public_methods:
                principal = Principal(subject="anonymous", tenant=md.get(cfg.tenant_header.lower()), method=method)
            else:
                if not token and not (cfg.allow_anonymous and not cfg.jwt_enabled):
                    _raise_unauthed("missing bearer token")
                claims = _jwt_decode(token, cfg) if (token and cfg.jwt_enabled) else {}
                if cfg.claims_validator:
                    cfg.claims_validator(claims, md)
                principal = _build_principal(claims, md, method, cn, fp, cfg)
                _check_required_scopes(principal, method, cfg)

            token_ctx = _principal_ctx.set(principal)
            try:
                async for resp in behavior(request, context):
                    yield resp
            finally:
                _principal_ctx.reset(token_ctx)
        return handler

    async def _awrap_stream_unary(behavior, cfg: AuthConfig):
        async def handler(request_iterator, context: aio.ServicerContext):
            method = context._rpc_event.call_details.method  # type: ignore[attr-defined]
            md = _metadata_to_dict(await context.invocation_metadata())  # type: ignore[func-returns-value]
            token = _extract_bearer_token(md)
            cn, fp = _parse_mtls(context)

            if method in cfg.public_methods:
                principal = Principal(subject="anonymous", tenant=md.get(cfg.tenant_header.lower()), method=method)
            else:
                if not token and not (cfg.allow_anonymous and not cfg.jwt_enabled):
                    _raise_unauthed("missing bearer token")
                claims = _jwt_decode(token, cfg) if (token and cfg.jwt_enabled) else {}
                if cfg.claims_validator:
                    cfg.claims_validator(claims, md)
                principal = _build_principal(claims, md, method, cn, fp, cfg)
                _check_required_scopes(principal, method, cfg)

            token_ctx = _principal_ctx.set(principal)
            try:
                return await behavior(request_iterator, context)
            finally:
                _principal_ctx.reset(token_ctx)
        return handler

    async def _awrap_stream_stream(behavior, cfg: AuthConfig):
        async def handler(request_iterator, context: aio.ServicerContext):
            method = context._rpc_event.call_details.method  # type: ignore[attr-defined]
            md = _metadata_to_dict(await context.invocation_metadata())  # type: ignore[func-returns-value]
            token = _extract_bearer_token(md)
            cn, fp = _parse_mtls(context)

            if method in cfg.public_methods:
                principal = Principal(subject="anonymous", tenant=md.get(cfg.tenant_header.lower()), method=method)
            else:
                if not token and not (cfg.allow_anonymous and not cfg.jwt_enabled):
                    _raise_unauthed("missing bearer token")
                claims = _jwt_decode(token, cfg) if (token and cfg.jwt_enabled) else {}
                if cfg.claims_validator:
                    cfg.claims_validator(claims, md)
                principal = _build_principal(claims, md, method, cn, fp, cfg)
                _check_required_scopes(principal, method, cfg)

            token_ctx = _principal_ctx.set(principal)
            try:
                async for resp in behavior(request_iterator, context):
                    yield resp
            finally:
                _principal_ctx.reset(token_ctx)
        return handler

    class AsyncAuthInterceptor(aio.ServerInterceptor):  # type: ignore[misc]
        """Асинхронный gRPC интерсептор (grpc.aio.Server)."""

        def __init__(self, config: AuthConfig) -> None:
            self._cfg = config

        async def intercept_service(self, continuation, handler_call_details):
            handler = await continuation(handler_call_details)

            if handler.unary_unary:
                return aio.unary_unary_rpc_method_handler(
                    await _awrap_unary_unary(handler.unary_unary, self._cfg),
                    request_deserializer=handler.request_deserializer,
                    response_serializer=handler.response_serializer,
                )
            if handler.unary_stream:
                return aio.unary_stream_rpc_method_handler(
                    await _awrap_unary_stream(handler.unary_stream, self._cfg),
                    request_deserializer=handler.request_deserializer,
                    response_serializer=handler.response_serializer,
                )
            if handler.stream_unary:
                return aio.stream_unary_rpc_method_handler(
                    await _awrap_stream_unary(handler.stream_unary, self._cfg),
                    request_deserializer=handler.request_deserializer,
                    response_serializer=handler.response_serializer,
                )
            if handler.stream_stream:
                return aio.stream_stream_rpc_method_handler(
                    await _awrap_stream_stream(handler.stream_stream, self._cfg),
                    request_deserializer=handler.request_deserializer,
                    response_serializer=handler.response_serializer,
                )
            return handler


# ------------------------------------------------------------------------------
# Пример инициализации (для серверов):
# ------------------------------------------------------------------------------
# from security_core.api.grpc.interceptors.auth import (
#     AuthInterceptor, AsyncAuthInterceptor, AuthConfig, HMACKeyProvider
# )
#
# cfg = AuthConfig(
#     allow_anonymous=False,
#     jwt_enabled=True,
#     issuer="https://issuer.example",
#     audience="security-core",
#     key_provider=HMACKeyProvider(default_secret=os.environ["AUTH_JWT_SECRET"]),
#     required_scopes_by_method={
#         "/aethernova.security.v1.AuthorizationService/CheckAccess": ["authz:check"],
#         "/aethernova.security.v1.PolicyAdminService/CreatePolicy": ["policy:write"],
#     },
#     public_methods=[
#         "/grpc.health.v1.Health/Check",
#     ],
# )
#
# # Sync server:
# server = grpc.server(futures.ThreadPoolExecutor(max_workers=16), interceptors=[AuthInterceptor(cfg)])
#
# # Async server:
# server = aio.server(interceptors=[AsyncAuthInterceptor(cfg)])
#
# # В обработчиках:
# pr = get_current_principal()
# if not pr or not pr.tenant:
#     context.abort(grpc.StatusCode.PERMISSION_DENIED, "tenant required")
