# -*- coding: utf-8 -*-
"""
OmniMind Core — gRPC Auth Interceptors (sync + asyncio)
-------------------------------------------------------

Функциональность:
- Источники идентичности: Bearer JWT, API-ключ, mTLS (CN/SAN allowlist).
- Авторизация: сопоставление RPC -> требуемые scopes/roles, deny-by-default.
- Кэширование: TTL-кэш решений аутентификации/интроспекции.
- Безопасность: маскирование чувствительных заголовков/метаданных, строгие коды ошибок.
- Наблюдаемость: структурированное логирование (без внешних зависимостей), корреляция request_id/trace_id.
- Универсальность: поддержка grpc.ServerInterceptor и grpc.aio.ServerInterceptor.
- Без опциональных зависимостей. Если установлен PyJWT — может быть использован автоматически.

Подключение (sync):
    server = grpc.server(futures.ThreadPoolExecutor(), interceptors=[
        AuthServerInterceptor(config=auth_config)
    ])

Подключение (asyncio):
    server = grpc.aio.server(interceptors=[AuthAioServerInterceptor(config=auth_config)])

Глоссарий метаданных:
- authorization: "Bearer <JWT>" или "ApiKey <KEY>"
- x-api-key: альтернативный заголовок для ключей
- x-tenant-id: явный тенант (если не в клеймах)
- x-request-id / x-trace-id: корреляция
"""

from __future__ import annotations

import abc
import base64
import functools
import json
import logging
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Set, Tuple

import grpc

# Опционально используем PyJWT, если он установлен
try:
    import jwt  # type: ignore
    _HAS_PYJWT = True
except Exception:
    _HAS_PYJWT = False

# ----------------------------- #
# Контекстные переменные (thread-local / task-local)
# ----------------------------- #

try:
    import contextvars
    _principal_ctx: "contextvars.ContextVar[Optional['Principal']]" = contextvars.ContextVar("omni_principal", default=None)
    _request_id_ctx: "contextvars.ContextVar[str]" = contextvars.ContextVar("omni_request_id", default="")
    _trace_id_ctx: "contextvars.ContextVar[str]" = contextvars.ContextVar("omni_trace_id", default="")
    def set_ctx_principal(p: Optional["Principal"]): _principal_ctx.set(p)
    def get_ctx_principal() -> Optional["Principal"]: return _principal_ctx.get()
    def set_ctx_req(req_id: str): _request_id_ctx.set(req_id)
    def get_ctx_req() -> str: return _request_id_ctx.get()
    def set_ctx_trc(trc_id: str): _trace_id_ctx.set(trc_id)
    def get_ctx_trc() -> str: return _trace_id_ctx.get()
except Exception:
    # На старых интерпретаторах fallback к threading.local
    _tl = threading.local()
    def set_ctx_principal(p): setattr(_tl, "principal", p)
    def get_ctx_principal(): return getattr(_tl, "principal", None)
    def set_ctx_req(x): setattr(_tl, "request_id", x)
    def get_ctx_req(): return getattr(_tl, "request_id", "")
    def set_ctx_trc(x): setattr(_tl, "trace_id", x)
    def get_ctx_trc(): return getattr(_tl, "trace_id", "")

# ----------------------------- #
# Модели и исключения
# ----------------------------- #

@dataclass(frozen=True)
class Principal:
    subject: str
    tenant_id: str
    scopes: Set[str] = field(default_factory=set)
    roles: Set[str] = field(default_factory=set)
    issuer: str = ""
    audience: str = ""
    token_id: str = ""  # jti
    auth_time: Optional[int] = None
    method: str = ""  # "jwt" | "apikey" | "mtls"
    extra: Dict[str, Any] = field(default_factory=dict)


class AuthError(Exception):
    def __init__(self, message: str, status: grpc.StatusCode = grpc.StatusCode.UNAUTHENTICATED, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.status = status
        self.details = details or {}


# ----------------------------- #
# Конфигурация
# ----------------------------- #

@dataclass
class AuthConfig:
    # Разрешённые способы
    enable_jwt: bool = True
    enable_api_key: bool = True
    enable_mtls: bool = False

    # Источники значений
    api_keys: Set[str] = field(default_factory=set)  # статический набор ключей
    api_key_header: str = "x-api-key"
    authorization_header: str = "authorization"

    # JWT ожидания (используются валидатором)
    jwt_issuers: Set[str] = field(default_factory=set)
    jwt_audiences: Set[str] = field(default_factory=set)
    jwt_algorithms: Set[str] = field(default_factory=lambda: {"RS256", "ES256", "HS256"})
    # Ключи/секреты. Для асимметрии лучше использовать кастомный валидатор или JWKS callback.
    jwt_hs_secrets: Dict[str, str] = field(default_factory=dict)  # issuer -> HMAC secret (если HS*)
    # Кастомные хуки
    jwt_validator: Optional[Callable[[str], Principal]] = None  # Если задан — PyJWT не требуется
    api_key_validator: Optional[Callable[[str], Principal]] = None
    # Интроспекция OAuth2 (опционально)
    token_introspection: Optional[Callable[[str], Principal]] = None

    # mTLS: список CN/SAN, которым доверяем (если enable_mtls)
    mtls_allowed_subjects: Set[str] = field(default_factory=set)

    # RBAC/Scope маппинг: полные имена RPC или регулярные выражения к набору scopes
    # Пример ключа: "/omnimind.core.v1.Planner/CreatePlan"
    method_scopes: Dict[str, Set[str]] = field(default_factory=dict)
    # Публичные методы (без аутентификации)
    public_methods: Set[str] = field(default_factory=set)
    # Явные deny методы
    denied_methods: Set[str] = field(default_factory=set)

    # Тенант по умолчанию и правила
    default_tenant_header: str = "x-tenant-id"
    allowed_tenants: Optional[Set[str]] = None  # None = любые

    # Метаданные корреляции
    request_id_header: str = "x-request-id"
    trace_id_header: str = "x-trace-id"

    # Маскирование чувствительных метаданных
    redact_metadata_keys: Set[str] = field(default_factory=lambda: {"authorization", "x-api-key"})

    # Кэширование результатов проверки
    cache_ttl_seconds: int = 60
    cache_max_size: int = 10_000

    # Логирование
    logger_name: str = "omnimind.grpc.auth"
    log_level: int = logging.INFO
    log_success: bool = True
    log_failure: bool = True


# ----------------------------- #
# Утилиты
# ----------------------------- #

def _metadata_to_dict(md: Sequence[Tuple[str, str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in md:
        out.setdefault(k.lower(), v)
    return out

def _mask_metadata(md: Dict[str, str], redact_keys: Set[str]) -> Dict[str, str]:
    res: Dict[str, str] = {}
    for k, v in md.items():
        res[k] = "***" if k.lower() in redact_keys else v
    return res

def _get_full_method_name(handler_call_details: grpc.HandlerCallDetails) -> str:
    # Уже в формате "/<package>.<Service>/<Method>"
    return handler_call_details.method or ""

def _now_s() -> int:
    return int(time.time())

# ----------------------------- #
# TTL-кэш
# ----------------------------- #

class TTLCache:
    def __init__(self, ttl: int, maxsize: int):
        self.ttl = max(1, ttl)
        self.maxsize = max(1, maxsize)
        self._store: Dict[str, Tuple[int, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            item = self._store.get(key)
            if not item:
                return None
            exp, val = item
            if exp < _now_s():
                self._store.pop(key, None)
                return None
            return val

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            if len(self._store) >= self.maxsize:
                # простая эвикция: удалить произвольный устаревший или первый
                self._store.pop(next(iter(self._store)), None)
            self._store[key] = (_now_s() + self.ttl, value)

# ----------------------------- #
# Валидаторы
# ----------------------------- #

class IdentityValidator(abc.ABC):
    @abc.abstractmethod
    def validate(self, token_or_key: str, md: Dict[str, str]) -> Principal:
        ...

class APIKeyValidator(IdentityValidator):
    def __init__(self, cfg: AuthConfig):
        self.cfg = cfg

    def validate(self, token_or_key: str, md: Dict[str, str]) -> Principal:
        # Кастомный валидатор приоритетнее
        if self.cfg.api_key_validator:
            return self.cfg.api_key_validator(token_or_key)

        if token_or_key not in self.cfg.api_keys:
            raise AuthError("invalid api key", grpc.StatusCode.UNAUTHENTICATED)
        tenant = md.get(self.cfg.default_tenant_header.lower(), "") or "default"
        return Principal(
            subject=f"apikey:{token_or_key[:6]}…",
            tenant_id=tenant,
            scopes=set(),
            roles={"apikey"},
            method="apikey",
        )

class JWTValidator(IdentityValidator):
    def __init__(self, cfg: AuthConfig):
        self.cfg = cfg

    def _validate_with_pyjwt(self, tok: str) -> Dict[str, Any]:
        # Поддержка HMAC-секретов по issuer, для RS/ES требуется кастомный jwt_validator или JWKS-провайдер.
        if not _HAS_PYJWT:
            raise AuthError("PyJWT is not installed and no custom jwt_validator provided", grpc.StatusCode.UNAUTHENTICATED)
        unverified = jwt.get_unverified_header(tok)
        alg = unverified.get("alg", "RS256")
        options = {"verify_aud": bool(self.cfg.jwt_audiences)}
        if alg.startswith("HS"):
            # Подбор секрета по iss
            payload = jwt.decode(
                tok,
                key=self._hs_secret_for(tok),
                algorithms=list(self.cfg.jwt_algorithms),
                audience=list(self.cfg.jwt_audiences) or None,
                options=options,
            )
        else:
            # Без публичного ключа PyJWT не сможет верифицировать подпись.
            # Для асимметричных алгоритмов используйте кастомный валидатор или JWKS.
            raise AuthError("asymmetric JWT validation requires custom validator or JWKS key", grpc.StatusCode.UNAUTHENTICATED)
        return payload

    def _hs_secret_for(self, tok: str) -> str:
        # Извлекаем iss без проверки подписи только для выбора секрета
        try:
            payload = jwt.decode(tok, options={"verify_signature": False})
            iss = payload.get("iss", "")
            secret = self.cfg.jwt_hs_secrets.get(iss)
            if not secret:
                raise AuthError("no HMAC secret for issuer", grpc.StatusCode.UNAUTHENTICATED)
            return secret
        except Exception as e:
            raise AuthError(f"invalid jwt format: {e}", grpc.StatusCode.UNAUTHENTICATED)

    def validate(self, token_or_key: str, md: Dict[str, str]) -> Principal:
        if self.cfg.jwt_validator:
            return self.cfg.jwt_validator(token_or_key)

        claims = self._validate_with_pyjwt(token_or_key)

        iss = str(claims.get("iss", ""))
        aud = claims.get("aud", "")
        sub = str(claims.get("sub", "")) or "unknown"
        tid = str(claims.get("tid", "")) or md.get(self.cfg.default_tenant_header.lower(), "") or "default"
        scp = claims.get("scope") or claims.get("scopes") or []
        if isinstance(scp, str):
            scopes = set(s.strip() for s in scp.split() if s.strip())
        else:
            scopes = set(scp)

        roles = set(claims.get("roles") or [])
        jti = str(claims.get("jti", ""))

        # Базовые проверки issuer/audience, если заданы в конфиге
        if self.cfg.jwt_issuers and iss not in self.cfg.jwt_issuers:
            raise AuthError("issuer not allowed", grpc.StatusCode.UNAUTHENTICATED)
        if self.cfg.jwt_audiences:
            aud_ok = False
            if isinstance(aud, str):
                aud_ok = aud in self.cfg.jwt_audiences
            elif isinstance(aud, list):
                aud_ok = bool(set(aud) & self.cfg.jwt_audiences)
            if not aud_ok:
                raise AuthError("audience not allowed", grpc.StatusCode.UNAUTHENTICATED)

        return Principal(
            subject=sub,
            tenant_id=tid,
            scopes=scopes,
            roles=roles,
            issuer=iss,
            audience=aud if isinstance(aud, str) else " ".join(aud) if isinstance(aud, list) else "",
            token_id=jti,
            auth_time=claims.get("auth_time"),
            method="jwt",
            extra={"claims": {k: v for k, v in claims.items() if k not in {"exp", "iat", "nbf"}}},
        )

# ----------------------------- #
# Core авторизация
# ----------------------------- #

class Authorizer:
    def __init__(self, cfg: AuthConfig):
        self.cfg = cfg
        self._api_validator = APIKeyValidator(cfg)
        self._jwt_validator = JWTValidator(cfg)
        self._cache = TTLCache(ttl=cfg.cache_ttl_seconds, maxsize=cfg.cache_max_size)
        self._log = logging.getLogger(cfg.logger_name)
        if not self._log.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter("%(message)s"))
            self._log.addHandler(h)
        self._log.setLevel(cfg.log_level)

    def authenticate(self, method: string, md_pairs: Sequence[Tuple[str, str]], peer: str, auth_ctx: Mapping[str, bytes]) -> Principal:
        md = _metadata_to_dict(md_pairs)
        req_id = md.get(self.cfg.request_id_header.lower()) or str(uuid.uuid4())
        trc_id = md.get(self.cfg.trace_id_header.lower()) or ""
        set_ctx_req(req_id)
        set_ctx_trc(trc_id)

        # Публичный/запрещённый метод
        if self._is_denied(method):
            raise AuthError("method denied", grpc.StatusCode.PERMISSION_DENIED)
        if self._is_public(method):
            p = Principal(subject="anonymous", tenant_id=md.get(self.cfg.default_tenant_header.lower(), "") or "public", method="public")
            set_ctx_principal(p)
            return p

        # Пробуем кэш (по токену/ключу)
        cache_key = self._cache_key(md)
        if cache_key:
            cached = self._cache.get(cache_key)
            if cached:
                set_ctx_principal(cached)
                return cached

        # Порядок: Authorization, X-API-Key, mTLS
        authz = md.get(self.cfg.authorization_header.lower(), "")
        api_key = md.get(self.cfg.api_key_header.lower(), "")

        principal: Optional[Principal] = None
        if authz:
            scheme, _, token = authz.partition(" ")
            scheme = scheme.lower()
            token = token.strip()
            if scheme == "bearer" and self.cfg.enable_jwt:
                principal = self._validate_jwt(token, md)
            elif scheme == "apikey" and self.cfg.enable_api_key:
                principal = self._validate_apikey(token, md)
            else:
                raise AuthError("unsupported authorization scheme", grpc.StatusCode.UNAUTHENTICATED)
        elif api_key and self.cfg.enable_api_key:
            principal = self._validate_apikey(api_key, md)
        elif self.cfg.enable_mtls:
            principal = self._validate_mtls(auth_ctx, md)
        else:
            raise AuthError("missing credentials", grpc.StatusCode.UNAUTHENTICATED)

        # Проверка тенанта
        if self.cfg.allowed_tenants is not None and principal.tenant_id not in self.cfg.allowed_tenants:
            raise AuthError("tenant not allowed", grpc.StatusCode.PERMISSION_DENIED)

        # Кэшируем
        if cache_key and principal:
            self._cache.set(cache_key, principal)

        set_ctx_principal(principal)
        return principal

    def authorize(self, method: str, principal: Principal) -> None:
        # Требуемые scopes для метода
        required = self._required_scopes_for(method)
        if not required:
            return
        if principal.scopes & required:
            return
        raise AuthError("insufficient scope", grpc.StatusCode.PERMISSION_DENIED, {"required": list(required)})

    # ---- helpers ----
    def _validate_apikey(self, key: str, md: Dict[str, str]) -> Principal:
        return self._api_validator.validate(key, md)

    def _validate_jwt(self, token: str, md: Dict[str, str]) -> Principal:
        if self.cfg.token_introspection:
            return self.cfg.token_introspection(token)
        return self._jwt_validator.validate(token, md)

    def _validate_mtls(self, auth_ctx: Mapping[str, bytes], md: Dict[str, str]) -> Principal:
        # auth_ctx может содержать 'x509_common_name' или 'x509_pem_cert'
        # Стратегия: CN должен входить в allowlist, иначе отказ.
        cn = ""
        try:
            # На некоторых билдах ключ — b"x509_common_name"
            cn = auth_ctx.get("x509_common_name") or auth_ctx.get(b"x509_common_name", b"").decode()  # type: ignore
            if isinstance(cn, bytes):
                cn = cn.decode()
        except Exception:
            cn = ""
        if not cn:
            raise AuthError("mtls identity not present", grpc.StatusCode.UNAUTHENTICATED)
        if self.cfg.mtls_allowed_subjects and cn not in self.cfg.mtls_allowed_subjects:
            raise AuthError("mtls subject not allowed", grpc.StatusCode.PERMISSION_DENIED)
        tenant = md.get(self.cfg.default_tenant_header.lower(), "") or "default"
        return Principal(subject=f"mtls:{cn}", tenant_id=tenant, roles={"mtls"}, method="mtls")

    def _is_public(self, method: str) -> bool:
        return method in self.cfg.public_methods or any(re.fullmatch(pat, method) for pat in self._regex_keys(self.cfg.public_methods))

    def _is_denied(self, method: str) -> bool:
        return method in self.cfg.denied_methods or any(re.fullmatch(pat, method) for pat in self._regex_keys(self.cfg.denied_methods))

    def _required_scopes_for(self, method: str) -> Set[str]:
        # Точное совпадение
        if method in self.cfg.method_scopes:
            return self.cfg.method_scopes[method]
        # Регулярные выражения
        for pat, scopes in self.cfg.method_scopes.items():
            try:
                if re.fullmatch(pat, method):
                    return scopes
            except re.error:
                continue
        return set()

    def _regex_keys(self, keys: Iterable[str]) -> Iterable[str]:
        # Оставляем только те, что выглядят как паттерны
        for k in keys:
            if any(ch in k for ch in ".*+?[](){}|\\"):
                yield k

    def _cache_key(self, md: Dict[str, str]) -> Optional[str]:
        authz = md.get(self.cfg.authorization_header.lower(), "")
        if authz:
            scheme, _, token = authz.partition(" ")
            token = token.strip()
            if token:
                return f"authz:{hash(token)}"
        api_key = md.get(self.cfg.api_key_header.lower(), "")
        if api_key:
            return f"apikey:{hash(api_key)}"
        return None

    def log_decision(self, *, method: str, md: Dict[str, str], principal: Optional[Principal], error: Optional[AuthError], duration_ms: float) -> None:
        do_log = (error and self.cfg.log_failure) or (not error and self.cfg.log_success)
        if not do_log:
            return
        payload = {
            "ts": int(time.time()),
            "service": "grpc",
            "method": method,
            "duration_ms": round(duration_ms, 3),
            "request_id": get_ctx_req(),
            "trace_id": get_ctx_trc(),
            "metadata": _mask_metadata(md, self.cfg.redact_metadata_keys),
        }
        if error:
            payload.update({"decision": "deny", "status": str(error.status), "reason": str(error), "details": error.details})
            self._log.log(logging.WARNING, json.dumps(payload, ensure_ascii=False))
        else:
            payload.update({"decision": "allow", "subject": principal.subject if principal else "anonymous", "tenant": principal.tenant_id if principal else ""})
            self._log.log(self.cfg.log_level, json.dumps(payload, ensure_ascii=False))


# ----------------------------- #
# gRPC Interceptors (sync)
# ----------------------------- #

class AuthServerInterceptor(grpc.ServerInterceptor):
    def __init__(self, config: AuthConfig):
        self.cfg = config
        self.authz = Authorizer(config)

    def intercept_service(self, continuation: Callable[[grpc.HandlerCallDetails], grpc.RpcMethodHandler], handler_call_details: grpc.HandlerCallDetails) -> grpc.RpcMethodHandler:
        method = _get_full_method_name(handler_call_details)
        handler = continuation(handler_call_details)
        if handler is None:
            return handler

        def _wrap_unary_unary(h):
            def _wrapper(request, context: grpc.ServicerContext):
                start = time.perf_counter()
                md_pairs = context.invocation_metadata() or []
                try:
                    p = self.authz.authenticate(method, md_pairs, context.peer(), context.auth_context())
                    self.authz.authorize(method, p)
                    resp = h(request, context)
                    return resp
                except AuthError as e:
                    context.set_trailing_metadata((("x-request-id", get_ctx_req()),))
                    self._abort(context, e)
                finally:
                    self.authz.log_decision(method=method, md=_metadata_to_dict(md_pairs), principal=get_ctx_principal(), error=None if context._state.code is None else AuthError(str(context._state.details), context._state.code), duration_ms=(time.perf_counter() - start) * 1000)
            return _wrapper

        def _wrap_unary_stream(h):
            def _wrapper(request, context: grpc.ServicerContext):
                start = time.perf_counter()
                md_pairs = context.invocation_metadata() or []
                try:
                    p = self.authz.authenticate(method, md_pairs, context.peer(), context.auth_context())
                    self.authz.authorize(method, p)
                    for resp in h(request, context):
                        yield resp
                except AuthError as e:
                    context.set_trailing_metadata((("x-request-id", get_ctx_req()),))
                    self._abort(context, e)
                finally:
                    self.authz.log_decision(method=method, md=_metadata_to_dict(md_pairs), principal=get_ctx_principal(), error=None if context._state.code is None else AuthError(str(context._state.details), context._state.code), duration_ms=(time.perf_counter() - start) * 1000)
            return _wrapper

        def _wrap_stream_unary(h):
            def _wrapper(request_iter, context: grpc.ServicerContext):
                start = time.perf_counter()
                md_pairs = context.invocation_metadata() or []
                try:
                    p = self.authz.authenticate(method, md_pairs, context.peer(), context.auth_context())
                    self.authz.authorize(method, p)
                    resp = h(request_iter, context)
                    return resp
                except AuthError as e:
                    context.set_trailing_metadata((("x-request-id", get_ctx_req()),))
                    self._abort(context, e)
                finally:
                    self.authz.log_decision(method=method, md=_metadata_to_dict(md_pairs), principal=get_ctx_principal(), error=None if context._state.code is None else AuthError(str(context._state.details), context._state.code), duration_ms=(time.perf_counter() - start) * 1000)
            return _wrapper

        def _wrap_stream_stream(h):
            def _wrapper(request_iter, context: grpc.ServicerContext):
                start = time.perf_counter()
                md_pairs = context.invocation_metadata() or []
                try:
                    p = self.authz.authenticate(method, md_pairs, context.peer(), context.auth_context())
                    self.authz.authorize(method, p)
                    for resp in h(request_iter, context):
                        yield resp
                except AuthError as e:
                    context.set_trailing_metadata((("x-request-id", get_ctx_req()),))
                    self._abort(context, e)
                finally:
                    self.authz.log_decision(method=method, md=_metadata_to_dict(md_pairs), principal=get_ctx_principal(), error=None if context._state.code is None else AuthError(str(context._state.details), context._state.code), duration_ms=(time.perf_counter() - start) * 1000)
            return _wrapper

        # Оборачиваем соответствующий тип
        if handler.unary_unary:
            return grpc.unary_unary_rpc_method_handler(
                _wrap_unary_unary(handler.unary_unary),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.unary_stream:
            return grpc.unary_stream_rpc_method_handler(
                _wrap_unary_stream(handler.unary_stream),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.stream_unary:
            return grpc.stream_unary_rpc_method_handler(
                _wrap_stream_unary(handler.stream_unary),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.stream_stream:
            return grpc.stream_stream_rpc_method_handler(
                _wrap_stream_stream(handler.stream_stream),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        return handler

    @staticmethod
    def _abort(context: grpc.ServicerContext, e: AuthError):
        # Проставим понятные детали и коды
        context.abort_with_status(grpc.StatusCode.to_status(e.status, details=str(e)))


# ----------------------------- #
# gRPC Interceptors (asyncio)
# ----------------------------- #

class AuthAioServerInterceptor(grpc.aio.ServerInterceptor):  # type: ignore[attr-defined]
    def __init__(self, config: AuthConfig):
        self.cfg = config
        self.authz = Authorizer(config)

    async def intercept_service(self, continuation, handler_call_details):
        method = _get_full_method_name(handler_call_details)
        handler = await continuation(handler_call_details)
        if handler is None:
            return handler

        async def _wrap_unary_unary(h):
            async def _wrapper(request, context: grpc.aio.ServicerContext):
                start = time.perf_counter()
                md_pairs = await context.invocation_metadata()
                err: Optional[AuthError] = None
                try:
                    p = self.authz.authenticate(method, md_pairs, context.peer(), context.auth_context())
                    self.authz.authorize(method, p)
                    return await h(request, context)
                except AuthError as e:
                    err = e
                    await context.send_trailing_metadata((("x-request-id", get_ctx_req()),))
                    await context.abort(e.status, str(e))
                finally:
                    self.authz.log_decision(method=method, md=_metadata_to_dict(md_pairs), principal=get_ctx_principal(), error=err, duration_ms=(time.perf_counter() - start) * 1000)
            return _wrapper

        async def _wrap_unary_stream(h):
            async def _wrapper(request, context: grpc.aio.ServicerContext):
                start = time.perf_counter()
                md_pairs = await context.invocation_metadata()
                err: Optional[AuthError] = None
                try:
                    p = self.authz.authenticate(method, md_pairs, context.peer(), context.auth_context())
                    self.authz.authorize(method, p)
                    async for resp in h(request, context):
                        yield resp
                except AuthError as e:
                    err = e
                    await context.send_trailing_metadata((("x-request-id", get_ctx_req()),))
                    await context.abort(e.status, str(e))
                finally:
                    self.authz.log_decision(method=method, md=_metadata_to_dict(md_pairs), principal=get_ctx_principal(), error=err, duration_ms=(time.perf_counter() - start) * 1000)
            return _wrapper

        async def _wrap_stream_unary(h):
            async def _wrapper(request_iter, context: grpc.aio.ServicerContext):
                start = time.perf_counter()
                md_pairs = await context.invocation_metadata()
                err: Optional[AuthError] = None
                try:
                    p = self.authz.authenticate(method, md_pairs, context.peer(), context.auth_context())
                    self.authz.authorize(method, p)
                    return await h(request_iter, context)
                except AuthError as e:
                    err = e
                    await context.send_trailing_metadata((("x-request-id", get_ctx_req()),))
                    await context.abort(e.status, str(e))
                finally:
                    self.authz.log_decision(method=method, md=_metadata_to_dict(md_pairs), principal=get_ctx_principal(), error=err, duration_ms=(time.perf_counter() - start) * 1000)
            return _wrapper

        async def _wrap_stream_stream(h):
            async def _wrapper(request_iter, context: grpc.aio.ServicerContext):
                start = time.perf_counter()
                md_pairs = await context.invocation_metadata()
                err: Optional[AuthError] = None
                try:
                    p = self.authz.authenticate(method, md_pairs, context.peer(), context.auth_context())
                    self.authz.authorize(method, p)
                    async for resp in h(request_iter, context):
                        yield resp
                except AuthError as e:
                    err = e
                    await context.send_trailing_metadata((("x-request-id", get_ctx_req()),))
                    await context.abort(e.status, str(e))
                finally:
                    self.authz.log_decision(method=method, md=_metadata_to_dict(md_pairs), principal=get_ctx_principal(), error=err, duration_ms=(time.perf_counter() - start) * 1000)
            return _wrapper

        if handler.unary_unary:
            return grpc.aio.unary_unary_rpc_method_handler(await _wrap_unary_unary(handler.unary_unary), request_deserializer=handler.request_deserializer, response_serializer=handler.response_serializer)
        if handler.unary_stream:
            return grpc.aio.unary_stream_rpc_method_handler(await _wrap_unary_stream(handler.unary_stream), request_deserializer=handler.request_deserializer, response_serializer=handler.response_serializer)
        if handler.stream_unary:
            return grpc.aio.stream_unary_rpc_method_handler(await _wrap_stream_unary(handler.stream_unary), request_deserializer=handler.request_deserializer, response_serializer=handler.response_serializer)
        if handler.stream_stream:
            return grpc.aio.stream_stream_rpc_method_handler(await _wrap_stream_stream(handler.stream_stream), request_deserializer=handler.request_deserializer, response_serializer=handler.response_serializer)
        return handler


# ----------------------------- #
# Пример минимальной конфигурации
# ----------------------------- #

def example_config() -> AuthConfig:
    return AuthConfig(
        enable_jwt=True,
        enable_api_key=True,
        enable_mtls=False,
        api_keys={"prod-KEY-123456"},
        jwt_issuers={"https://auth.example.com"},
        jwt_audiences={"omnimind-core"},
        jwt_hs_secrets={"https://auth.example.com": "REPLACE_WITH_SECURE_SECRET"},
        public_methods={"/omnimind.core.v1.Health/Check"},
        method_scopes={
            r"/omnimind\.core\.v1\.Planner/.*": {"planner:write"},
            r"/omnimind\.core\.v1\.Executor/ExecutePlan": {"executor:run"},
        },
        allowed_tenants={"omni", "sandbox"},
    )
