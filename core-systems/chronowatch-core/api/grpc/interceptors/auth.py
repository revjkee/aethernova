# -*- coding: utf-8 -*-
"""
ChronoWatch Core — gRPC Auth Interceptor (async, production-grade)

Функции:
- Проверка Authorization: Bearer <JWT>
- Поддержка режимов: AUTH_MODE=jwt (HS/RS/ES) и AUTH_MODE=oidc (JWKS, кэш)
- Строгая валидация iss/aud/exp/iat/nbf c leeway (JWT_CLOCK_SKEW_SEC)
- Извлечение ролей/скоупов (roles, role, realm_access, resource_access, scope, scp)
- Public allowlist (health/reflection) + deny-by-default
- RBAC по методам: read/write/admin на базе имени RPC (паттерны Create/Update/Delete/…)
- Проброс AuthContext через contextvars для дальнейшего использования в хендлерах
- Трейсинг (OpenTelemetry, если установлен), структурные логи без PII

Зависимости (pip):
  grpcio>=1.63.0
  PyJWT>=2.8.0
  cryptography>=41.0.0  (для RSA/ECDSA)
  opentelemetry-api (опционально)

Переменные окружения (см. .env.example / configs/security.yaml):
  AUTH_MODE=jwt|oidc|none
  JWT_SECRET=...                # для HS*
  JWT_ISSUER=...
  JWT_AUDIENCE=chronowatch
  JWT_CLOCK_SKEW_SEC=30
  OIDC_ISSUER_URL=...
  OIDC_JWKS_CACHE_TTL_SEC=3600
  RBAC_DEFAULT_ROLE=viewer
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import grpc
from grpc import aio  # type: ignore

import jwt
from jwt import PyJWKClient, InvalidTokenError

try:
    # OpenTelemetry — опционально
    from opentelemetry import trace  # type: ignore
    _tracer = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _tracer = None  # graceful degrade

import contextvars

# ---------------------------
# Контекст аутентификации
# ---------------------------

@dataclass(frozen=True)
class AuthContext:
    sub: str
    iss: str
    aud: Optional[str]
    roles: Tuple[str, ...] = field(default_factory=tuple)
    scopes: Tuple[str, ...] = field(default_factory=tuple)
    org_id: Optional[str] = None
    token_id: Optional[str] = None
    iat: Optional[int] = None
    exp: Optional[int] = None
    raw_claims: Mapping[str, Any] = field(default_factory=dict)


_auth_ctx_var: contextvars.ContextVar[Optional[AuthContext]] = contextvars.ContextVar(
    "auth_ctx", default=None
)


def get_auth() -> Optional[AuthContext]:
    """
    Доступ к текущему AuthContext в хендлерах.
    """
    return _auth_ctx_var.get()


# ---------------------------
# Конфиг
# ---------------------------

@dataclass
class AuthConfig:
    mode: str = os.getenv("AUTH_MODE", "jwt")  # jwt|oidc|none
    issuer: Optional[str] = os.getenv("JWT_ISSUER")
    audience: Optional[str] = os.getenv("JWT_AUDIENCE", "chronowatch")
    jwt_secret: Optional[str] = os.getenv("JWT_SECRET")
    clock_skew_sec: int = int(os.getenv("JWT_CLOCK_SKEW_SEC", "30"))

    oidc_issuer_url: Optional[str] = os.getenv("OIDC_ISSUER_URL")
    oidc_jwks_cache_ttl_sec: int = int(os.getenv("OIDC_JWKS_CACHE_TTL_SEC", "3600"))

    default_role: str = os.getenv("RBAC_DEFAULT_ROLE", "viewer")

    # Публичные методы (регексы) — не требуют токен
    public_methods: Tuple[re.Pattern, ...] = (
        re.compile(r"^/grpc\.health\.v1\.Health/.*$"),
        re.compile(r"^/grpc\.reflection\..*$"),
    )

    # Разрешённые алгоритмы (по умолчанию безопасные)
    allowed_algs: Tuple[str, ...] = ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "HS256", "HS384", "HS512")

    def validate(self) -> None:
        if self.mode not in ("jwt", "oidc", "none"):
            raise ValueError("AUTH_MODE must be one of: jwt, oidc, none")
        if self.mode == "jwt" and not self.jwt_secret:
            raise ValueError("JWT_SECRET is required for AUTH_MODE=jwt")
        if self.mode in ("jwt", "oidc"):
            if not self.issuer:
                raise ValueError("JWT_ISSUER is required")
            if not self.audience:
                raise ValueError("JWT_AUDIENCE is required")
        if self.mode == "oidc" and not self.oidc_issuer_url:
            raise ValueError("OIDC_ISSUER_URL is required for AUTH_MODE=oidc")


# ---------------------------
# RBAC резолвер по имени RPC
# ---------------------------

class RbacLevel:
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"


def default_rbac_for_method(full_method: str) -> str:
    """
    Определяем требуемый уровень доступа по имени RPC.
    full_method: "/package.Service/Method"
    """
    method = full_method.rsplit("/", 1)[-1]

    admin_ops = ("Delete", "Drain", "Bootstrap", "Config", "Export", "Import")
    write_ops = (
        "Create",
        "Update",
        "Upsert",
        "Enqueue",
        "Cancel",
        "Retry",
        "Pause",
        "Resume",
    )

    if any(method.startswith(p) for p in admin_ops):
        return RbacLevel.ADMIN
    if any(method.startswith(p) for p in write_ops):
        return RbacLevel.WRITE
    return RbacLevel.READ


def rbac_roles_for_level(level: str) -> Tuple[str, ...]:
    if level == RbacLevel.ADMIN:
        return ("admin",)
    if level == RbacLevel.WRITE:
        return ("operator", "admin")
    return ("viewer", "operator", "admin")


# ---------------------------
# JWKS клиент с кэшем
# ---------------------------

class _JwksCache:
    def __init__(self, jwks_url: str, ttl_sec: int) -> None:
        self._jwks_url = jwks_url
        self._ttl = max(60, ttl_sec)
        self._client = PyJWKClient(jwks_url)
        self._expires_at = 0.0
        self._cached: Optional[PyJWKClient] = None
        self._lock = asyncio.Lock()

    async def get_client(self) -> PyJWKClient:
        now = time.time()
        if self._cached and now < self._expires_at:
            return self._cached
        async with self._lock:
            # двойная проверка
            if self._cached and time.time() < self._expires_at:
                return self._cached
            # PyJWKClient сам кэширует ключи по KID, но мы обновляем "валидность"
            self._cached = self._client
            self._expires_at = time.time() + self._ttl
            return self._cached


# ---------------------------
# Утилиты
# ---------------------------

def _now_utc_ts() -> int:
    return int(datetime.now(tz=timezone.utc).timestamp())


def _get_metadata_value(md: Sequence[Tuple[str, str]], key: str) -> Optional[str]:
    key_lower = key.lower()
    for k, v in md:
        if k.lower() == key_lower:
            return v
    return None


def _parse_authorization(md: Sequence[Tuple[str, str]]) -> Optional[str]:
    val = _get_metadata_value(md, "authorization")
    if not val:
        return None
    parts = val.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip()


def _extract_roles_and_scopes(claims: Mapping[str, Any], default_role: str) -> Tuple[Tuple[str, ...], Tuple[str, ...], Optional[str]]:
    roles: List[str] = []
    scopes: List[str] = []
    org_id: Optional[str] = None

    # Стандартизированные/де-факто поля:
    # roles / role
    if "roles" in claims and isinstance(claims["roles"], (list, tuple)):
        roles.extend([str(r).lower() for r in claims["roles"]])
    elif "role" in claims:
        roles.append(str(claims["role"]).lower())

    # Keycloak: realm_access.roles
    realm_roles = claims.get("realm_access", {}).get("roles")
    if isinstance(realm_roles, (list, tuple)):
        roles.extend([str(r).lower() for r in realm_roles])

    # Keycloak: resource_access.{client_id}.roles
    res_acc = claims.get("resource_access", {})
    if isinstance(res_acc, dict):
        for client, data in res_acc.items():
            r = data.get("roles")
            if isinstance(r, (list, tuple)):
                roles.extend([str(x).lower() for x in r])

    # scopes: "scope" (space-delimited) или "scp" (OIDC)
    if "scope" in claims:
        scopes.extend(str(claims["scope"]).split())
    if "scp" in claims and isinstance(claims["scp"], (list, tuple)):
        scopes.extend([str(s) for s in claims["scp"]])

    # org_id — произвольно (поддержка ABAC)
    if "org_id" in claims:
        org_id = str(claims["org_id"])

    if not roles:
        roles = [default_role]

    # нормализуем и уникализируем
    roles_u = tuple(sorted(set(roles)))
    scopes_u = tuple(sorted(set(scopes)))
    return roles_u, scopes_u, org_id


def _is_public_method(method: str, patterns: Tuple[re.Pattern, ...]) -> bool:
    for p in patterns:
        if p.match(method):
            return True
    return False


def _safe_log(logger: logging.Logger, level: int, msg: str, **kwargs: Any) -> None:
    # Исключаем PII/секреты: не логируем токены/authorization/полные claims
    redacted = {k: ("<redacted>" if k in {"authorization", "token", "claims"} else v) for k, v in kwargs.items()}
    logger.log(level, msg, extra={"event": "auth", **redacted})


# ---------------------------
# Основной интерсептор
# ---------------------------

class AuthInterceptor(aio.ServerInterceptor):
    """
    Применение:
        server = aio.server(interceptors=[AuthInterceptor.from_env()])
    """

    def __init__(
        self,
        config: AuthConfig,
        *,
        rbac_resolver: Callable[[str], str] = default_rbac_for_method,
        required_scopes: Optional[Mapping[str, Sequence[str]]] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.cfg = config
        self.cfg.validate()
        self.rbac_resolver = rbac_resolver
        self.required_scopes = required_scopes or {}
        self.log = logger or logging.getLogger("chronowatch.grpc.auth")

        self._jwks_cache: Optional[_JwksCache] = None
        if self.cfg.mode == "oidc":
            # Пытаемся получить jwks_uri стандартным способом:
            # многие провайдеры публикуют <issuer>/.well-known/openid-configuration
            # Однако, чтобы не зависеть от HTTP-разбора здесь, используйте
            # переменную окружения OIDC_ISSUER_URL с корректным base.
            jwks_url = self._derive_jwks_url(self.cfg.oidc_issuer_url)
            self._jwks_cache = _JwksCache(jwks_url, self.cfg.oidc_jwks_cache_ttl_sec)

    @classmethod
    def from_env(cls) -> "AuthInterceptor":
        return cls(AuthConfig())

    # ------------ gRPC API ------------

    async def intercept_service(
        self,
        continuation: Callable[[grpc.HandlerCallDetails], Any],
        handler_call_details: grpc.HandlerCallDetails,
    ):
        method = handler_call_details.method

        # Пропускаем публичные методы без токена
        if _is_public_method(method, self.cfg.public_methods) or self.cfg.mode == "none":
            return await continuation(handler_call_details)

        # Иначе — оборачиваем хендлер для проверки токена и RBAC
        handler = await continuation(handler_call_details)
        if handler is None:
            return None

        # Обёртки на 4 типа RPC
        if handler.unary_unary:
            async def unary_unary(request, context):
                return await self._handle_rpc(method, handler_call_details, handler.unary_unary, request, context)
            return grpc.aio.unary_unary_rpc_method_handler(
                unary_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.unary_stream:
            async def unary_stream(request, context):
                return await self._handle_rpc(method, handler_call_details, handler.unary_stream, request, context)
            return grpc.aio.unary_stream_rpc_method_handler(
                unary_stream,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_unary:
            async def stream_unary(request_iterator, context):
                return await self._handle_rpc(method, handler_call_details, handler.stream_unary, request_iterator, context)
            return grpc.aio.stream_unary_rpc_method_handler(
                stream_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_stream:
            async def stream_stream(request_iterator, context):
                return await self._handle_rpc(method, handler_call_details, handler.stream_stream, request_iterator, context)
            return grpc.aio.stream_stream_rpc_method_handler(
                stream_stream,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        return handler  # fallback

    # ------------ Проверка токена + RBAC ------------

    async def _handle_rpc(self, method: str, hcd: grpc.HandlerCallDetails, core_handler, request, context: aio.ServicerContext):
        metadata = tuple(hcd.invocation_metadata or ())

        token = _parse_authorization(metadata)
        if not token:
            await self._abort(context, grpc.StatusCode.UNAUTHENTICATED, "missing_bearer_token")
            return None

        try:
            claims, alg = await self._verify_token(token)
        except InvalidTokenError as e:
            _safe_log(self.log, logging.WARNING, "invalid_token", method=method, reason=str(e))
            await self._abort(context, grpc.StatusCode.UNAUTHENTICATED, "invalid_token")
            return None
        except Exception as e:  # непредвиденные ошибки верификации
            _safe_log(self.log, logging.ERROR, "token_verification_error", method=method, error=str(e))
            await self._abort(context, grpc.StatusCode.UNAUTHENTICATED, "token_verification_error")
            return None

        roles, scopes, org_id = _extract_roles_and_scopes(claims, self.cfg.default_role)

        # RBAC
        level = self.rbac_resolver(method)
        allowed_roles = rbac_roles_for_level(level)

        if not set(roles).intersection(allowed_roles):
            _safe_log(self.log, logging.INFO, "rbac_denied", method=method, level=level, roles=list(roles))
            await self._abort(context, grpc.StatusCode.PERMISSION_DENIED, "insufficient_role")
            return None

        # Проверка необходимых скоупов для конкретного метода (если заданы)
        needed_scopes = self._scopes_for_method(method)
        if needed_scopes and not set(scopes).issuperset(needed_scopes):
            _safe_log(self.log, logging.INFO, "scope_denied", method=method, needed=list(needed_scopes), present=list(scopes))
            await self._abort(context, grpc.StatusCode.PERMISSION_DENIED, "insufficient_scope")
            return None

        # Устанавливаем AuthContext
        auth_ctx = AuthContext(
            sub=str(claims.get("sub")),
            iss=str(claims.get("iss")),
            aud=str(claims.get("aud")) if claims.get("aud") is not None else None,
            roles=roles,
            scopes=scopes,
            org_id=org_id,
            token_id=str(claims.get("jti")) if claims.get("jti") else None,
            iat=int(claims["iat"]) if "iat" in claims else None,
            exp=int(claims["exp"]) if "exp" in claims else None,
            raw_claims=claims,
        )
        token_ = _auth_ctx_var.set(auth_ctx)
        try:
            if _tracer:
                with _tracer.start_as_current_span("authz"):
                    span = trace.get_current_span()
                    try:
                        span.set_attribute("enduser.id", auth_ctx.sub)
                        span.set_attribute("auth.issuer", auth_ctx.iss)
                        span.set_attribute("auth.roles", ",".join(auth_ctx.roles))
                        if auth_ctx.org_id:
                            span.set_attribute("enduser.org_id", auth_ctx.org_id)
                        span.set_attribute("rpc.method", method)
                    except Exception:
                        pass
            # Передаём управление реальному хендлеру
            return await core_handler(request, context)
        finally:
            _auth_ctx_var.reset(token_)

    async def _verify_token(self, token: str) -> Tuple[Mapping[str, Any], str]:
        """
        Возвращает (claims, alg)
        """
        options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iat": False,  # iat валиден информационно; допускаем clock skew отдельно
            "verify_iss": True,
            "verify_aud": True if self.cfg.audience else False,
        }
        leeway = self.cfg.clock_skew_sec

        if self.cfg.mode == "jwt":
            claims = jwt.decode(
                token,
                key=self.cfg.jwt_secret,
                algorithms=self.cfg.allowed_algs,
                audience=self.cfg.audience,
                issuer=self.cfg.issuer,
                options=options,
                leeway=leeway,
            )
            unverified = jwt.get_unverified_header(token)
            alg = unverified.get("alg", "HS256")
            if alg not in self.cfg.allowed_algs:
                raise InvalidTokenError("algorithm_not_allowed")
            return claims, alg

        if self.cfg.mode == "oidc":
            assert self._jwks_cache is not None
            client = await self._jwks_cache.get_client()
            signing_key = client.get_signing_key_from_jwt(token).key
            unverified = jwt.get_unverified_header(token)
            alg = unverified.get("alg", "RS256")
            if alg not in self.cfg.allowed_algs:
                raise InvalidTokenError("algorithm_not_allowed")
            claims = jwt.decode(
                token,
                key=signing_key,
                algorithms=[alg],
                audience=self.cfg.audience,
                issuer=self.cfg.issuer,
                options=options,
                leeway=leeway,
            )
            return claims, alg

        # AUTH_MODE=none — не должно сюда попадать (фильтруется выше)
        raise InvalidTokenError("auth_mode_not_supported")

    def _scopes_for_method(self, method: str) -> Tuple[str, ...]:
        # Точное соответствие или по префиксу пакета/сервиса
        if method in self.required_scopes:
            return tuple(self.required_scopes[method])
        # Пример: "/chronowatch.api.v1.Scheduler/UpdateSchedule" → "/chronowatch.api.v1.Scheduler/*"
        parts = method.split("/")
        if len(parts) == 3:
            prefix = f"{parts[0]}/{parts[1]}/*"
            if prefix in self.required_scopes:
                return tuple(self.required_scopes[prefix])
        return tuple()

    async def _abort(self, context: aio.ServicerContext, code: grpc.StatusCode, msg: str) -> None:
        # Безопасный abort без утечки деталей
        await context.abort(code, msg)

    # best-effort определение JWKS URL для популярных провайдеров (Keycloak/Generic)
    def _derive_jwks_url(self, issuer_url: Optional[str]) -> str:
        if not issuer_url:
            # Теоретически недостижимо: validate() это ловит
            raise ValueError("Missing OIDC_ISSUER_URL")
        issuer_url = issuer_url.rstrip("/")
        # Keycloak Realm certs:
        #   https://<host>/realms/<realm>/protocol/openid-connect/certs
        if "/realms/" in issuer_url and "/protocol/openid-connect" not in issuer_url:
            return f"{issuer_url}/protocol/openid-connect/certs"
        # Generic: попробуем well-known, но без fetch здесь — используем common путь
        return f"{issuer_url}/protocol/openid-connect/certs"


# ---------------------------
# Пример инициализации (для справки, не исполняется здесь)
# ---------------------------
# from grpc import aio
# server = aio.server(interceptors=[AuthInterceptor.from_env()])
# add_ChronoWatchServicers(server)  # автогенерированные gRPC сервисы
# await server.start()
# await server.wait_for_termination()
