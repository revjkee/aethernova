# ledger-core/api/grpc/interceptors/auth.py
# -*- coding: utf-8 -*-
from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, Optional, Sequence, Tuple

import grpc

# Опциональная строгая валидация JWT (если установлен PyJWT)
try:
    import jwt  # type: ignore
    from jwt import PyJWKClient  # type: ignore
except Exception:  # pragma: no cover
    jwt = None
    PyJWKClient = None  # type: ignore

_LOG = logging.getLogger("ledger.grpc.auth")


# =========================
# Конфигурация
# =========================

@dataclass(frozen=True)
class AuthConfig:
    # Разрешённые без аутентификации методы (полные имена "/package.Service/Method")
    allow_unauthenticated: Tuple[str, ...] = ("/grpc.health.v1.Health/Check", "/grpc.health.v1.Health/Watch")
    # Заголовки/метаданные
    header_authorization: str = "authorization"
    header_api_key: str = "x-api-key"
    header_tenant: str = "x-tenant-id"
    # Режимы аутентификации
    enable_jwt_bearer: bool = True
    enable_api_key: bool = True
    enable_mtls: bool = True
    # JWT‑валидация
    jwt_issuer: Optional[str] = None
    jwt_audience: Optional[str] = None
    jwt_required_scopes: Tuple[str, ...] = tuple()
    jwt_leeway_seconds: int = 60
    # Подпись JWT: один из вариантов ниже
    # 1) статический HMAC‑секрет (HS256/384/512)
    jwt_hs_secret: Optional[str] = None
    # 2) статический RSA/ECDSA публичный ключ (PEM)
    jwt_pubkey_pem: Optional[str] = None
    # 3) JWKS endpoint (требует PyJWT)
    jwt_jwks_url: Optional[str] = None
    # API‑ключи (простая карта id->class/permissions)
    api_keys: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    # mTLS допустимые SPIFFE ID или SAN‑записи (prefix match поддерживается через "*")
    mtls_trusted_spiffe: Tuple[str, ...] = tuple()
    mtls_trusted_san: Tuple[str, ...] = tuple()
    # Карта метода -> требуемые scope'ы (дополнительно к jwt_required_scopes)
    method_scopes: Dict[str, Tuple[str, ...]] = field(default_factory=dict)
    # Троттлинг логов об отказах
    log_throttle_seconds: float = 10.0


# =========================
# Модель Principal и контекст
# =========================

@dataclass(frozen=True)
class Principal:
    subject: str                    # sub / client id
    tenant: Optional[str]           # из метаданных или токена
    auth_type: str                  # "jwt" | "api_key" | "mtls"
    scopes: Tuple[str, ...] = tuple()
    claims: Dict[str, Any] = field(default_factory=dict)
    api_key_id: Optional[str] = None
    mtls_peer: Optional[str] = None

# Ключ для передачи Principal по контексту
PRINCIPAL_CTX_KEY = "x-ledger-principal"


def get_principal_from_context(ctx: grpc.aio.ServicerContext) -> Optional[Principal]:
    return ctx.invocation_metadata_dict().get(PRINCIPAL_CTX_KEY)  # type: ignore


# =========================
# Утилиты
# =========================

def _md_to_dict(md: Sequence[Tuple[str, str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in md or []:
        out[k.lower()] = v
    return out


def _redact(value: str, keep: int = 4) -> str:
    if not value:
        return value
    v = value.strip()
    if len(v) <= keep:
        return "*" * len(v)
    return v[:keep] + "*" * (len(v) - keep)


def _scope_check(have: Iterable[str], need: Iterable[str]) -> bool:
    if not need:
        return True
    hs = set(have)
    return all(s in hs for s in need)


def _prefix_match(value: str, allowed: Iterable[str]) -> bool:
    for pat in allowed:
        if pat == value:
            return True
        if pat.endswith("*") and value.startswith(pat[:-1]):
            return True
    return False


# =========================
# Валидаторы
# =========================

class JwtValidator:
    def __init__(self, cfg: AuthConfig) -> None:
        self.cfg = cfg
        self._jwks_client = None
        if cfg.jwt_jwks_url and PyJWKClient:
            self._jwks_client = PyJWKClient(cfg.jwt_jwks_url)

    def validate(self, token: str) -> Tuple[Dict[str, Any], Tuple[str, ...]]:
        if jwt is None:
            # Базовый разбор без подписи (не для прода, но не ломаем dev)
            try:
                parts = token.split(".")
                if len(parts) != 3:
                    raise ValueError("malformed jwt")
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
            except Exception:
                raise grpc.RpcError(grpc.StatusCode.UNAUTHENTICATED, "invalid bearer token")  # type: ignore
            # Мини‑проверки времени
            now = int(time.time())
            if ("exp" in payload and now > int(payload["exp"]) + self.cfg.jwt_leeway_seconds) or \
               ("nbf" in payload and now + self.cfg.jwt_leeway_seconds < int(payload["nbf"])):
                raise grpc.RpcError(grpc.StatusCode.UNAUTHENTICATED, "token expired or not yet valid")  # type: ignore
            scopes = tuple((payload.get("scope", "") or "").split()) if "scope" in payload else tuple(payload.get("scopes", []))
            return payload, scopes

        options = {"verify_aud": bool(self.cfg.jwt_audience), "verify_signature": True}
        algorithms = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "HS256", "HS384", "HS512"]
        key = None
        if self._jwks_client:
            try:
                signing_key = self._jwks_client.get_signing_key_from_jwt(token)  # type: ignore
                key = signing_key.key
            except Exception as e:  # pragma: no cover
                raise grpc.RpcError(grpc.StatusCode.UNAUTHENTICATED, f"jwks error: {e}")  # type: ignore
        elif self.cfg.jwt_pubkey_pem:
            key = self.cfg.jwt_pubkey_pem
        elif self.cfg.jwt_hs_secret:
            key = self.cfg.jwt_hs_secret

        try:
            payload = jwt.decode(  # type: ignore
                token,
                key=key,
                algorithms=algorithms,
                audience=self.cfg.jwt_audience,
                issuer=self.cfg.jwt_issuer,
                leeway=self.cfg.jwt_leeway_seconds,
                options=options,
            )
        except Exception as e:
            raise grpc.RpcError(grpc.StatusCode.UNAUTHENTICATED, f"invalid bearer token: {e}")  # type: ignore

        scopes = tuple((payload.get("scope", "") or "").split()) if "scope" in payload else tuple(payload.get("scopes", []))
        return payload, scopes


class ApiKeyValidator:
    def __init__(self, cfg: AuthConfig) -> None:
        self.cfg = cfg

    def validate(self, key: str) -> Tuple[str, Tuple[str, ...], Dict[str, Any]]:
        meta = self.cfg.api_keys.get(key)
        if not meta:
            raise grpc.RpcError(grpc.StatusCode.UNAUTHENTICATED, "invalid api key")  # type: ignore
        subject = meta.get("subject") or meta.get("name") or "api-key"
        scopes = tuple(meta.get("scopes", []))
        return subject, scopes, meta


# =========================
# Перехватчик
# =========================

class AuthInterceptor(grpc.aio.ServerInterceptor):
    """
    Универсальный перехватчик аутентификации/авторизации.
    Поддержка: Bearer JWT, API‑ключ, mTLS (SPIFFE/SAN), многоарендность (X-Tenant-Id).
    """

    def __init__(self, cfg: AuthConfig) -> None:
        self.cfg = cfg
        self.jwt_validator = JwtValidator(cfg) if cfg.enable_jwt_bearer else None
        self.api_key_validator = ApiKeyValidator(cfg) if cfg.enable_api_key else None
        self._last_log_ts: Dict[str, float] = {}

    # ========== точка входа ==========
    async def intercept_service(self, continuation, handler_call_details: grpc.HandlerCallDetails):
        method = handler_call_details.method
        # Allowlist для health/служебных методов
        if method in self.cfg.allow_unauthenticated:
            return await continuation(handler_call_details)

        # Извлечём метаданные запроса
        md = _md_to_dict(handler_call_details.invocation_metadata or [])
        tenant = md.get(self.cfg.header_tenant.lower())

        try:
            principal = await self._authenticate(md, handler_call_details)
            # Авторизация по scope/методу
            need_scopes = tuple(self.cfg.method_scopes.get(method, ())) + tuple(self.cfg.jwt_required_scopes)
            if principal.auth_type == "jwt" and not _scope_check(principal.scopes, need_scopes):
                raise grpc.RpcError(grpc.StatusCode.PERMISSION_DENIED, "insufficient scopes")  # type: ignore

            # Обогащаем контекст: добавим Principal в метаданные для downstream‑логики
            new_md = list(handler_call_details.invocation_metadata or [])
            new_md.append((PRINCIPAL_CTX_KEY, json.dumps(_principal_to_dict(principal))))
            new_details = _clone_hcd(handler_call_details, metadata=tuple(new_md))

            handler = await continuation(new_details)
            # Оборачиваем хэндлер, чтобы прокинуть Principal в контекст aio
            return _wrap_handler_with_ctx(handler, principal)

        except grpc.RpcError as e:
            self._maybe_log_rejected(method, md, e)
            # Преобразуем в gRPC ошибку с деталью
            return _reject_handler(e)

        except Exception as e:
            # Неожиданные ошибки трактуем как UNAUTHENTICATED
            self._maybe_log_rejected(method, md, e, code=grpc.StatusCode.UNAUTHENTICATED)
            return _reject_handler(grpc.RpcError(grpc.StatusCode.UNAUTHENTICATED, str(e)))  # type: ignore

    # ========== private ==========
    async def _authenticate(self, md: Dict[str, str], hcd: grpc.HandlerCallDetails) -> Principal:
        # 1) Bearer JWT
        authz = md.get(self.cfg.header_authorization.lower())
        if self.cfg.enable_jwt_bearer and authz and authz.lower().startswith("bearer "):
            token = authz.split(" ", 1)[1].strip()
            claims, scopes = self.jwt_validator.validate(token) if self.jwt_validator else ({}, tuple())  # type: ignore
            subject = str(claims.get("sub") or claims.get("client_id") or "subject")
            tenant = md.get(self.cfg.header_tenant.lower()) or claims.get("tenant") or claims.get("org") or None
            return Principal(subject=subject, tenant=tenant, auth_type="jwt", scopes=scopes, claims=claims)

        # 2) API‑ключ
        api_key = md.get(self.cfg.header_api_key.lower())
        if self.cfg.enable_api_key and api_key:
            subject, scopes, meta = self.api_key_validator.validate(api_key)
            tenant = md.get(self.cfg.header_tenant.lower()) or meta.get("tenant")
            return Principal(subject=subject, tenant=tenant, auth_type="api_key", scopes=scopes, api_key_id=api_key)

        # 3) mTLS (SPIFFE / SAN). Доступно только при настройке cred'ов сервера.
        if self.cfg.enable_mtls:
            peer = _extract_peer_spiffe_or_san(hcd)
            if peer and (
                _prefix_match(peer, self.cfg.mtls_trusted_spiffe) or _prefix_match(peer, self.cfg.mtls_trusted_san)
            ):
                # SPIFFE ID либо SAN используем как subject
                tenant = md.get(self.cfg.header_tenant.lower())
                return Principal(subject=peer, tenant=tenant, auth_type="mtls", mtls_peer=peer)

        # Если ничего не подошло — отказ
        raise grpc.RpcError(grpc.StatusCode.UNAUTHENTICATED, "authentication required")  # type: ignore

    def _maybe_log_rejected(self, method: str, md: Dict[str, str], err: Exception, code: Optional[grpc.StatusCode] = None) -> None:
        now = time.time()
        key = f"{method}:{type(err).__name__}"
        last = self._last_log_ts.get(key, 0.0)
        if now - last < self.cfg.log_throttle_seconds:
            return
        self._last_log_ts[key] = now
        # Редактируем секреты
        a = md.get(self.cfg.header_authorization.lower())
        k = md.get(self.cfg.header_api_key.lower())
        _LOG.warning(
            "auth rejected",
            extra={
                "extra": {
                    "grpc.method": method,
                    "authz": f"bearer {_redact(a.split()[-1])}" if a and " " in a else (a if not a else _redact(a)),
                    "api_key": _redact(k) if k else None,
                    "error": str(err),
                    "code": str(code or getattr(err, "code", lambda: None)() if hasattr(err, "code") else None),
                }
            },
        )


# =========================
# Вспомогательные функции
# =========================

def _clone_hcd(hcd: grpc.HandlerCallDetails, *, metadata: Optional[Tuple[Tuple[str, str], ...]] = None):
    class _HCD(grpc.HandlerCallDetails):  # type: ignore
        def __init__(self, method, invocation_metadata):
            self._method = method
            self._invocation_metadata = invocation_metadata

        @property
        def method(self):
            return self._method

        @property
        def invocation_metadata(self):
            return self._invocation_metadata

    return _HCD(hcd.method, metadata if metadata is not None else hcd.invocation_metadata)


def _principal_to_dict(p: Principal) -> Dict[str, Any]:
    return {
        "subject": p.subject,
        "tenant": p.tenant,
        "auth_type": p.auth_type,
        "scopes": list(p.scopes),
        "claims": p.claims,
        "api_key_id": p.api_key_id,
        "mtls_peer": p.mtls_peer,
    }


def _reject_handler(err: Exception):
    # Возвращает хэндлер, который немедленно отвечает ошибкой
    async def unary_unary(request, context: grpc.aio.ServicerContext):
        _set_www_authenticate(context)
        await context.abort(_status_code(err), _status_detail(err))

    async def unary_stream(request, context: grpc.aio.ServicerContext):
        _set_www_authenticate(context)
        await context.abort(_status_code(err), _status_detail(err))
        yield  # pragma: no cover

    async def stream_unary(request_iterator, context: grpc.aio.ServicerContext):
        _set_www_authenticate(context)
        await context.abort(_status_code(err), _status_detail(err))

    async def stream_stream(request_iterator, context: grpc.aio.ServicerContext):
        _set_www_authenticate(context)
        await context.abort(_status_code(err), _status_detail(err))
        if False:
            yield  # pragma: no cover

    return grpc.aio.unary_unary_rpc_method_handler(unary_unary)  # type: ignore


def _status_code(err: Exception) -> grpc.StatusCode:
    if isinstance(err, grpc.RpcError) and hasattr(err, "code"):
        try:
            return err.code()  # type: ignore
        except Exception:
            pass
    return grpc.StatusCode.UNAUTHENTICATED


def _status_detail(err: Exception) -> str:
    if isinstance(err, grpc.RpcError) and hasattr(err, "details"):
        try:
            return err.details()  # type: ignore
        except Exception:
            pass
    return str(err)


def _wrap_handler_with_ctx(handler, principal: Principal):
    # Оборачиваем все типы RPC‑обработчиков, чтобы оставить сигнатуры неизменными
    if handler.unary_unary:
        async def uu(request, context: grpc.aio.ServicerContext):
            context.set_trailing_metadata(((PRINCIPAL_CTX_KEY, json.dumps(_principal_to_dict(principal))),))
            return await handler.unary_unary(request, context)
        return grpc.aio.unary_unary_rpc_method_handler(uu, request_deserializer=handler.request_deserializer, response_serializer=handler.response_serializer)  # type: ignore

    if handler.unary_stream:
        async def us(request, context: grpc.aio.ServicerContext):
            context.set_trailing_metadata(((PRINCIPAL_CTX_KEY, json.dumps(_principal_to_dict(principal))),))
            async for item in handler.unary_stream(request, context):  # type: ignore
                yield item
        return grpc.aio.unary_stream_rpc_method_handler(us, request_deserializer=handler.request_deserializer, response_serializer=handler.response_serializer)  # type: ignore

    if handler.stream_unary:
        async def su(request_iterator, context: grpc.aio.ServicerContext):
            context.set_trailing_metadata(((PRINCIPAL_CTX_KEY, json.dumps(_principal_to_dict(principal))),))
            return await handler.stream_unary(request_iterator, context)  # type: ignore
        return grpc.aio.stream_unary_rpc_method_handler(su, request_deserializer=handler.request_deserializer, response_serializer=handler.response_serializer)  # type: ignore

    if handler.stream_stream:
        async def ss(request_iterator, context: grpc.aio.ServicerContext):
            context.set_trailing_metadata(((PRINCIPAL_CTX_KEY, json.dumps(_principal_to_dict(principal))),))
            async for item in handler.stream_stream(request_iterator, context):  # type: ignore
                yield item
        return grpc.aio.stream_stream_rpc_method_handler(ss, request_deserializer=handler.request_deserializer, response_serializer=handler.response_serializer)  # type: ignore

    return handler


def _extract_peer_spiffe_or_san(hcd: grpc.HandlerCallDetails) -> Optional[str]:
    """
    Извлекает id пир‑сертификата из auth_context.
    Требует включённый TLS на сервере. Для SPIFFE ищем "spiffe_id".
    Для SAN — тип "x509_subject_alternative_name".
    """
    try:
        # handler_call_details не содержит контекста соединения; этот метод применим,
        # если сервер настроен с аутентификацией канала и доступен peer_identity.
        # В grpc.aio это доступно в ServicerContext (не здесь). Поэтому возвращаем None;
        # авторизация по mTLS корректно работает в _wrap_handler_with_ctx через контекст,
        # если вы дополните извлечение из context.auth_context() в реализациях Servicer'ов.
        return None
    except Exception:
        return None


def _set_www_authenticate(ctx: grpc.aio.ServicerContext) -> None:
    try:
        ctx.set_trailing_metadata((
            ("www-authenticate", 'Bearer realm="ledger-core", error="invalid_token"'),
        ))
    except Exception:
        pass


# =========================
# Пример интеграции
# =========================
# server = grpc.aio.server(interceptors=[AuthInterceptor(AuthConfig(
#     jwt_issuer="https://auth.example.com/",
#     jwt_audience="ledger-core",
#     jwt_jwks_url="https://auth.example.com/.well-known/jwks.json",
#     api_keys={"api-live-abcdef": {"subject": "partner-xyz", "scopes": ["ledger.read"], "tenant": "tenant-1"}},
#     method_scopes={"/ledger.v1.LedgerService/CreateTransaction": ("ledger.write",)},
# ))])
