from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple

import grpc
from grpc.aio import ServerInterceptor
from jwt import PyJWKClient, InvalidTokenError, decode as jwt_decode, PyJWTError  # type: ignore

_LOG = logging.getLogger("datafabric.grpc.auth")

# =========================
# Конфигурация / модели
# =========================

@dataclass(frozen=True)
class MethodPolicy:
    """Политика доступа для группы методов."""
    any_roles: Tuple[str, ...] = tuple()
    all_roles: Tuple[str, ...] = tuple()
    required_tenant_claim: Optional[str] = "tenant"  # имя клейма с тенантом
    allow_service_accounts: bool = True             # разрешить service account (client_credentials)
    allow_mtls: bool = True                         # разрешить аутентификацию по mTLS peer cert

@dataclass(frozen=True)
class AuthConfig:
    issuer: str                                     # ожидаемый iss
    audience: str                                   # ожидаемый aud
    jwks_uri: Optional[str] = None                  # URI JWKS для PyJWKClient (если используете сетевой доступ)
    allowed_algs: Tuple[str, ...] = ("RS256", "ES256")
    clock_skew_sec: int = 60                        # допуск расхождения часов
    # Маппинг: префикс сервиса -> политика, например "datafabric.v1.Admin/" -> MethodPolicy(...)
    method_policies: Mapping[str, MethodPolicy] = field(default_factory=dict)
    # Заголовки метаданных клиента
    request_id_header: str = "x-request-id"
    tenant_header: str = "x-tenant-id"
    # Названия клеймов в токене
    roles_claim: str = "roles"
    scope_claim: str = "scope"
    subject_claim: str = "sub"
    tenant_claim: str = "tenant"
    # Поддержка SAN/Subject из peer‑cert для mTLS
    mTLS_san_as_sub: bool = True

# Представление аутентифицированного субъекта
@dataclass(frozen=True)
class Principal:
    sub: str
    roles: Tuple[str, ...] = tuple()
    scopes: Tuple[str, ...] = tuple()
    tenant: Optional[str] = None
    iss: Optional[str] = None
    aud: Optional[str] = None
    auth_type: str = "jwt"  # jwt|mtls

PRINCIPAL_CTX_KEY = "datafabric.principal"  # ключ для grpc.ServicerContext.set_trailing_metadata? см. ниже

# =========================
# JWKS провайдеры
# =========================

class JwksProvider(Protocol):
    """Абстракция для получения ключей валидации JWT."""
    def decode(self, token: str, *, issuer: str, audience: str, algorithms: Sequence[str], leeway: int) -> Dict[str, Any]: ...

class PyJwkClientProvider:
    """Провайдер на базе PyJWKClient (может ходить в сеть при наличии jwks_uri)."""
    def __init__(self, jwks_uri: Optional[str]) -> None:
        self._client = PyJWKClient(jwks_uri) if jwks_uri else None

    def decode(self, token: str, *, issuer: str, audience: str, algorithms: Sequence[str], leeway: int) -> Dict[str, Any]:
        # Если есть jwks_uri — используем подбор ключа, иначе даем jwt_decode шанс (например, с локальными ключами через options)
        if self._client:
            signing_key = self._client.get_signing_key_from_jwt(token)
            return jwt_decode(
                token,
                signing_key.key,
                algorithms=list(algorithms),
                audience=audience,
                issuer=issuer,
                leeway=leeway,
            )
        # Без клиента PyJWKClient — попробуем декодировать без ключа (например, симметричный/преднастроенный через ENV)
        return jwt_decode(
            token,
            options={"verify_signature": False, "verify_aud": True, "verify_iss": True, "verify_exp": True, "verify_nbf": True},
            algorithms=list(algorithms),
            audience=audience,
            issuer=issuer,
            leeway=leeway,
        )

# =========================
# Утилиты
# =========================

def _get_md(context: grpc.aio.ServicerContext) -> Dict[str, str]:
    md = {}
    try:
        for k, v in context.invocation_metadata():
            md[k.lower()] = v
    except Exception:
        pass
    return md

def _extract_bearer(md: Mapping[str, str]) -> Optional[str]:
    auth = md.get("authorization") or md.get("grpcgateway-authorization")
    if not auth:
        return None
    parts = auth.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer" and parts[1]:
        return parts[1].strip()
    return None

def _match_policy(method: str, policies: Mapping[str, MethodPolicy]) -> Optional[MethodPolicy]:
    # Ищем самый длинный префикс
    best = None
    best_len = -1
    for prefix, pol in policies.items():
        if method.startswith(prefix) and len(prefix) > best_len:
            best = pol
            best_len = len(prefix)
    return best

def _scopes_from_claim(value: Any) -> Tuple[str, ...]:
    if not value:
        return tuple()
    if isinstance(value, str):
        return tuple(x for x in value.split() if x)
    if isinstance(value, (list, tuple)):
        return tuple(str(x) for x in value)
    return tuple()

def _roles_from_claim(value: Any) -> Tuple[str, ...]:
    if not value:
        return tuple()
    if isinstance(value, str):
        # допускаем CSV
        parts = [x.strip() for x in value.split(",")]
        return tuple(p for p in parts if p)
    if isinstance(value, (list, tuple)):
        return tuple(str(x) for x in value)
    return tuple()

def _unauthenticated(details: str, request_id: Optional[str] = None) -> grpc.RpcError:
    trailers = []
    if request_id:
        trailers.append(("x-request-id", request_id))
    return grpc.aio.abort_with_status(grpc.StatusCode.UNAUTHENTICATED, details, trailers=trailers)

def _permission_denied(details: str, request_id: Optional[str] = None) -> grpc.RpcError:
    trailers = []
    if request_id:
        trailers.append(("x-request-id", request_id))
    return grpc.aio.abort_with_status(grpc.StatusCode.PERMISSION_DENIED, details, trailers=trailers)

def _principal_to_bin(pr: Principal) -> bytes:
    return json.dumps({
        "sub": pr.sub,
        "roles": pr.roles,
        "scopes": pr.scopes,
        "tenant": pr.tenant,
        "iss": pr.iss,
        "aud": pr.aud,
        "auth_type": pr.auth_type,
    }, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

# =========================
# Interceptor (grpc.aio)
# =========================

class AuthInterceptor(ServerInterceptor):
    """
    gRPC aio‑перехватчик аутентификации/авторизации.
    - Проверяет Bearer JWT согласно AuthConfig/JWKS
    - Поддерживает mTLS на основе peer cert (SAN/Subject) при allow_mtls=True
    - Применяет MethodPolicy по RPC‑методу
    - Прокидывает Principal в метаданные (context.set_trailing_metadata недоступен до завершения; используем context.set_invocation_metadata через хак — wrapper в handler)
    """

    def __init__(self, config: AuthConfig, jwks: Optional[JwksProvider] = None) -> None:
        self.cfg = config
        self.jwks = jwks or PyJwkClientProvider(config.jwks_uri)

    async def intercept_service(self, continuation: Callable, handler_call_details: grpc.HandlerCallDetails):
        method = handler_call_details.method or ""
        policy = _match_policy(method, self.cfg.method_policies)
        # Если политика не найдена — по умолчанию требуем аутентификацию
        if policy is None:
            policy = MethodPolicy()

        # Извлекаем метаданные
        md_pairs = handler_call_details.invocation_metadata or ()
        md: Dict[str, str] = {k.lower(): v for k, v in md_pairs}
        request_id = md.get(self.cfg.request_id_header.lower())

        principal: Optional[Principal] = None
        err: Optional[grpc.RpcError] = None

        # 1) Попытка JWT
        try:
            token = _extract_bearer(md)
            if token:
                claims = self.jwks.decode(
                    token,
                    issuer=self.cfg.issuer,
                    audience=self.cfg.audience,
                    algorithms=self.cfg.allowed_algs,
                    leeway=self.cfg.clock_skew_sec,
                )
                roles = _roles_from_claim(claims.get(self.cfg.roles_claim))
                scopes = _scopes_from_claim(claims.get(self.cfg.scope_claim))
                tenant = (claims.get(self.cfg.tenant_claim) or claims.get(policy.required_tenant_claim)) if policy.required_tenant_claim else None
                sub = claims.get(self.cfg.subject_claim) or "unknown"
                principal = Principal(
                    sub=sub,
                    roles=roles,
                    scopes=scopes,
                    tenant=tenant,
                    iss=str(claims.get("iss")),
                    aud=(claims.get("aud") if isinstance(claims.get("aud"), str) else self.cfg.audience),
                    auth_type="jwt",
                )
        except (InvalidTokenError, PyJWTError) as e:
            _LOG.warning("JWT rejected: %s", repr(e))
            # не прерываем сразу — дадим шанс mTLS, если разрешено
        except Exception as e:  # неожиданные ошибки — это UNAUTHENTICATED
            _LOG.exception("JWT validation error")
            return _unauthenticated("invalid authentication", request_id)

        # 2) Попытка mTLS (если разрешено и JWT не установил principal)
        if principal is None and policy.allow_mtls:
            try:
                # Для aio контекст недоступен здесь; обернем continuation и прочтём auth_context после binding
                handler = await continuation(handler_call_details)
                return self._wrap_mtls(handler, policy, request_id)
            except Exception:
                return _unauthenticated("mtls authentication failed", request_id)

        # Если ни JWT ни mTLS — ошибка
        if principal is None:
            return _unauthenticated("missing or invalid credentials", request_id)

        # 3) Авторизация по ролям/тенанту
        if not self._is_authorized(principal, policy):
            return _permission_denied("insufficient permissions", request_id)

        # 4) Проброс Principal в handler через модификацию метаданных (custom bin header)
        pr_bin = _principal_to_bin(principal)
        new_md = list(md_pairs) + [(b"x-principal-bin", pr_bin)]
        new_details = grpc.HandlerCallDetails(handler_call_details.method, tuple(new_md))
        handler = await continuation(new_details)
        return handler

    def _is_authorized(self, pr: Principal, policy: MethodPolicy) -> bool:
        rset = set(pr.roles or ())
        if policy.any_roles and not (set(policy.any_roles) & rset):
            return False
        if policy.all_roles and not set(policy.all_roles).issubset(rset):
            return False
        if policy.required_tenant_claim and pr.tenant is None:
            return False
        return True

    def _wrap_mtls(self, handler, policy: MethodPolicy, request_id: Optional[str]):
        # Оборачиваем unary_unary / unary_stream / stream_unary / stream_stream
        # чтобы прочесть peer‑cert из контекста, собрать Principal и проверить policy.
        def _mtls_principal(context: grpc.aio.ServicerContext) -> Optional[Principal]:
            try:
                ac = context.auth_context()
                # peer_identity_property_name == b"x509_base64_der"
                certs = ac.get("x509_pem_cert") or ac.get("x509_base64_der")
                if not certs:
                    return None
                # Берем первый сертификат
                cert_raw = certs[0]
                if isinstance(cert_raw, bytes):
                    der = cert_raw
                else:
                    der = cert_raw.encode("utf-8")
                sub = "mtls:" + base64.urlsafe_b64encode(der[:24]).decode("ascii").rstrip("=")
                pr = Principal(sub=sub, roles=("service.account",), scopes=tuple(), tenant=None, iss=None, aud=None, auth_type="mtls")
                return pr
            except Exception:
                return None

        async def _unary_unary(request, context: grpc.aio.ServicerContext):
            pr = _mtls_principal(context)
            if pr is None:
                await _unauthenticated("mtls authentication failed", request_id)
                return  # unreachable
            if not self._is_authorized(pr, policy):
                await _permission_denied("insufficient permissions", request_id)
                return
            # Прокинем principal в метаданные ответа
            context.set_trailing_metadata((("x-auth-type", pr.auth_type),))
            return await handler.unary_unary(request, context)

        async def _unary_stream(request, context: grpc.aio.ServicerContext):
            pr = _mtls_principal(context)
            if pr is None:
                await _unauthenticated("mtls authentication failed", request_id)
                return
            if not self._is_authorized(pr, policy):
                await _permission_denied("insufficient permissions", request_id)
                return
            context.set_trailing_metadata((("x-auth-type", pr.auth_type),))
            async for resp in handler.unary_stream(request, context):
                yield resp

        async def _stream_unary(request_iterator, context: grpc.aio.ServicerContext):
            pr = _mtls_principal(context)
            if pr is None:
                await _unauthenticated("mtls authentication failed", request_id)
                return
            if not self._is_authorized(pr, policy):
                await _permission_denied("insufficient permissions", request_id)
                return
            context.set_trailing_metadata((("x-auth-type", pr.auth_type),))
            return await handler.stream_unary(request_iterator, context)

        async def _stream_stream(request_iterator, context: grpc.aio.ServicerContext):
            pr = _mtls_principal(context)
            if pr is None:
                await _unauthenticated("mtls authentication failed", request_id)
                return
            if not self._is_authorized(pr, policy):
                await _permission_denied("insufficient permissions", request_id)
                return
            context.set_trailing_metadata((("x-auth-type", pr.auth_type),))
            async for resp in handler.stream_stream(request_iterator, context):
                yield resp

        if handler.unary_unary:
            return grpc.aio.unary_unary_rpc_method_handler(_unary_unary, request_deserializer=handler.request_deserializer, response_serializer=handler.response_serializer)
        if handler.unary_stream:
            return grpc.aio.unary_stream_rpc_method_handler(_unary_stream, request_deserializer=handler.request_deserializer, response_serializer=handler.response_serializer)
        if handler.stream_unary:
            return grpc.aio.stream_unary_rpc_method_handler(_stream_unary, request_deserializer=handler.request_deserializer, response_serializer=handler.response_serializer)
        if handler.stream_stream:
            return grpc.aio.stream_stream_rpc_method_handler(_stream_stream, request_deserializer=handler.request_deserializer, response_serializer=handler.response_serializer)
        return handler  # fallback

# =========================
# Пример инициализации
# =========================
"""
from grpc.aio import server
from api.grpc.interceptors.auth import AuthInterceptor, AuthConfig, MethodPolicy

cfg = AuthConfig(
    issuer="https://idp.example.com/",
    audience="datafabric-core",
    jwks_uri="https://idp.example.com/.well-known/jwks.json",
    method_policies={
        "/datafabric.v1.Admin/": MethodPolicy(any_roles=("platform.admin", "tenant.admin")),
        "/datafabric.v1.Quality/Validate": MethodPolicy(any_roles=("platform.admin","tenant.admin","tenant.reader")),
    },
)

srv = server(interceptors=[AuthInterceptor(cfg)])
# ... add your servicers
"""

# =========================
# Обработчики получения Principal в сервисе
# =========================

def extract_principal_from_metadata(context: grpc.ServicerContext) -> Optional[Principal]:
    """Получить Principal, сохраненный перехватчиком (для JWT‑пути)."""
    try:
        md = {k.lower(): v for k, v in context.invocation_metadata()}
        raw = md.get("x-principal-bin")
        if not raw:
            return None
        if isinstance(raw, bytes):
            data = raw
        else:
            data = raw.encode("utf-8")
        obj = json.loads(data.decode("utf-8"))
        return Principal(
            sub=obj.get("sub",""),
            roles=tuple(obj.get("roles", [])),
            scopes=tuple(obj.get("scopes", [])),
            tenant=obj.get("tenant"),
            iss=obj.get("iss"),
            aud=obj.get("aud"),
            auth_type=obj.get("auth_type","jwt"),
        )
    except Exception:
        return None
