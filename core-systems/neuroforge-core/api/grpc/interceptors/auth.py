# file: neuroforge-core/api/grpc/interceptors/auth.py
from __future__ import annotations

import hmac
import hashlib
import uuid
import fnmatch
import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, Union
import contextvars
import grpc

try:
    from grpc import aio as grpc_aio  # type: ignore
except Exception:  # pragma: no cover
    grpc_aio = None  # type: ignore

logger = logging.getLogger(__name__)

# ==============================================================================
# Доменные модели и контекст
# ==============================================================================

@dataclass(frozen=True)
class Principal:
    subject: str
    tenant: Optional[str] = None
    roles: Set[str] = field(default_factory=set)
    scopes: Set[str] = field(default_factory=set)
    token_id: Optional[str] = None
    issued_at: Optional[int] = None
    expires_at: Optional[int] = None
    auth_method: str = "unknown"  # bearer|api_key|mtls|unknown


_principal_ctx: contextvars.ContextVar[Optional[Principal]] = contextvars.ContextVar(
    "neuroforge_grpc_principal", default=None
)

def get_current_principal() -> Optional[Principal]:
    """Доступ к Principal внутри gRPC-обработчиков."""
    return _principal_ctx.get()

# ==============================================================================
# Исключения и интерфейсы верификации
# ==============================================================================

class AuthError(Exception):
    """Ошибка аутентификации."""
    def __init__(self, message: str = "unauthenticated") -> None:
        super().__init__(message)

class AuthorizationError(Exception):
    """Ошибка авторизации (недостаточно прав)."""
    def __init__(self, message: str = "permission denied") -> None:
        super().__init__(message)

# Пользовательский интерфейс для проверки Bearer-токенов (JWT/JWS и т.п.)
VerifyBearerFn = Callable[[str, Mapping[str, str]], Principal]
# Для API-ключей можно использовать встроенный ApiKeyVerifier ниже.
class BearerVerifier:
    """Интерфейс верификатора Bearer-токенов."""
    def verify(self, token: str, headers: Mapping[str, str]) -> Principal:  # pragma: no cover - интерфейс
        raise NotImplementedError

@dataclass
class ApiKeyVerifier:
    """
    Верификатор API-ключей по хэшам (sha256) с константно-временным сравнением.
    Хэши задаются в hex (нижний регистр). Источник можно обновлять на лету.
    """
    allowed_sha256_hex: Callable[[], Iterable[str]]

    def verify(self, raw_key: str, headers: Mapping[str, str]) -> Principal:
        digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        allowed = False
        for h in self.allowed_sha256_hex():
            if h and hmac.compare_digest(digest, h.strip()):
                allowed = True
                break
        if not allowed:
            raise AuthError("invalid api key")
        tenant = headers.get("x-tenant-id")
        return Principal(
            subject="api-key",
            tenant=tenant,
            roles={"api_key"},
            scopes=set(),
            token_id=digest,
            auth_method="api_key",
        )

# ==============================================================================
# Настройки и политика
# ==============================================================================

@dataclass(frozen=True)
class AuthPolicy:
    """
    Политика проверки доступа:
      - allow_unauthenticated: список шаблонов методов, которые не требуют аутентификации
      - required_scopes: карта шаблонов методов -> требуемые scope (должны все входить в principal.scopes)
      - required_roles:  карта шаблонов методов -> требуемые роли (хватает пересечения, если require_all_roles=False)
    """
    allow_unauthenticated: Tuple[str, ...] = (
        # Примеры: health и метаданные
        "*/Health/*",
        "*/Info/*",
    )
    required_scopes: Mapping[str, Set[str]] = field(default_factory=dict)
    required_roles: Mapping[str, Set[str]] = field(default_factory=dict)
    require_all_roles: bool = False

    def method_is_open(self, full_method: str) -> bool:
        return any(fnmatch.fnmatch(full_method, p) for p in self.allow_unauthenticated)

    def scopes_for(self, full_method: str) -> Set[str]:
        out: Set[str] = set()
        for patt, scopes in self.required_scopes.items():
            if fnmatch.fnmatch(full_method, patt):
                out.update(scopes)
        return out

    def roles_for(self, full_method: str) -> Set[str]:
        out: Set[str] = set()
        for patt, roles in self.required_roles.items():
            if fnmatch.fnmatch(full_method, patt):
                out.update(roles)
        return out

@dataclass(frozen=True)
class AuthSettings:
    accept_bearer: bool = True
    accept_api_key: bool = True
    accept_mtls: bool = False  # потребует внешнего маппера, см. mtls_mapper ниже
    # Имена метаданных
    header_authorization: str = "authorization"
    header_api_key: str = "x-api-key"
    header_request_id: str = "x-request-id"
    header_tenant_id: str = "x-tenant-id"
    # Префикс схемы для Bearer:
    bearer_scheme: str = "bearer"  # сравнивается case-insensitive

# Коллбек для маппинга mTLS peer -> Principal (если включено)
MtlsMapper = Callable[[Mapping[str, str]], Optional[Principal]]

# ==============================================================================
# Перехватчик
# ==============================================================================

class _AuthCore:
    """
    Общая логика аутентификации/авторизации, используемая sync и async перехватчиками.
    """

    def __init__(
        self,
        settings: AuthSettings,
        policy: AuthPolicy,
        bearer_verifier: Optional[Union[BearerVerifier, VerifyBearerFn]] = None,
        api_key_verifier: Optional[ApiKeyVerifier] = None,
        mtls_mapper: Optional[MtlsMapper] = None,
    ) -> None:
        self._s = settings
        self._p = policy
        self._bearer_verifier = bearer_verifier
        self._api_key_verifier = api_key_verifier
        self._mtls_mapper = mtls_mapper

    # ---- helpers ----

    def _normalize_metadata(self, md: Optional[Sequence[Tuple[str, str]]]) -> Dict[str, str]:
        out: Dict[str, str] = {}
        if not md:
            return out
        for k, v in md:
            lk = k.lower()
            # сохраняем последнее значение (gRPC допускает дубликаты)
            out[lk] = v
        return out

    def _extract_request_id(self, md: Mapping[str, str]) -> str:
        rid = md.get(self._s.header_request_id)
        return rid if rid else str(uuid.uuid4())

    def _auth_bearer(self, md: Mapping[str, str]) -> Optional[Principal]:
        if not self._s.accept_bearer or not self._bearer_verifier:
            return None
        auth = md.get(self._s.header_authorization)
        if not auth:
            return None
        parts = auth.split(None, 1)
        if len(parts) != 2 or parts[0].lower() != self._s.bearer_scheme:
            # чужая схема — игнорируем
            return None
        token = parts[1].strip()
        if not token:
            raise AuthError("empty bearer token")
        try:
            if isinstance(self._bearer_verifier, BearerVerifier):
                princ = self._bearer_verifier.verify(token, md)
            else:
                princ = self._bearer_verifier(token, md)  # type: ignore
            return princ
        except AuthError:
            raise
        except Exception as e:
            logger.debug("bearer verification failed: %s", e, exc_info=logger.isEnabledFor(logging.DEBUG))
            raise AuthError("invalid bearer token")

    def _auth_api_key(self, md: Mapping[str, str]) -> Optional[Principal]:
        if not self._s.accept_api_key or not self._api_key_verifier:
            return None
        raw = md.get(self._s.header_api_key)
        if not raw:
            return None
        return self._api_key_verifier.verify(raw, md)

    def _auth_mtls(self, peer_md: Mapping[str, str]) -> Optional[Principal]:
        if not self._s.accept_mtls or not self._mtls_mapper:
            return None
        try:
            return self._mtls_mapper(peer_md)
        except Exception as e:
            logger.debug("mtls mapping failed: %s", e, exc_info=logger.isEnabledFor(logging.DEBUG))
            raise AuthError("invalid mtls identity")

    def _authorize(self, principal: Principal, full_method: str) -> None:
        # Требуемые scopes
        req_scopes = self._p.scopes_for(full_method)
        if req_scopes and not req_scopes.issubset(principal.scopes):
            missing = ", ".join(sorted(req_scopes - principal.scopes))
            raise AuthorizationError(f"missing scopes: {missing}")
        # Роли
        req_roles = self._p.roles_for(full_method)
        if req_roles:
            inter = principal.roles.intersection(req_roles)
            if self._p.require_all_roles:
                if not req_roles.issubset(principal.roles):
                    missing = ", ".join(sorted(req_roles - principal.roles))
                    raise AuthorizationError(f"missing roles: {missing}")
            else:
                if not inter:
                    need = ", ".join(sorted(req_roles))
                    raise AuthorizationError(f"required any role: {need}")

    # ---- основной вход ----

    def authenticate_and_authorize(
        self,
        full_method: str,
        invocation_metadata: Optional[Sequence[Tuple[str, str]]],
        peer_auth_md: Optional[Mapping[str, str]] = None,
    ) -> Tuple[Optional[Principal], str]:
        """
        Возвращает (principal|None, request_id).
        Может бросить AuthError/AuthorizationError.
        """
        md = self._normalize_metadata(invocation_metadata)
        req_id = self._extract_request_id(md)

        if self._p.method_is_open(full_method):
            return None, req_id  # доступ без аутентификации

        # Порядок: Bearer -> API Key -> mTLS
        err: Optional[Exception] = None
        for provider in ("bearer", "api_key", "mtls"):
            try:
                if provider == "bearer":
                    princ = self._auth_bearer(md)
                elif provider == "api_key":
                    princ = self._auth_api_key(md)
                else:
                    princ = self._auth_mtls(peer_auth_md or {})
                if princ:
                    # Авторизация
                    self._authorize(princ, full_method)
                    return princ, req_id
            except (AuthError, AuthorizationError) as e:
                err = e
                break  # важная ошибка — прекращаем

        # Если сюда дошли — не представили валидных кредов
        if err:
            raise err
        raise AuthError("credentials not provided")

# ==============================================================================
# Sync перехватчик (grpc.ServerInterceptor)
# ==============================================================================

class AuthInterceptor(grpc.ServerInterceptor):
    """
    Пример подключения:
        server = grpc.server(futures.ThreadPoolExecutor(), interceptors=[
            AuthInterceptor(settings, policy, bearer_verifier=my_jwt, api_key_verifier=my_keys, mtls_mapper=my_mtls)
        ])
    """

    def __init__(
        self,
        settings: AuthSettings,
        policy: AuthPolicy,
        bearer_verifier: Optional[Union[BearerVerifier, VerifyBearerFn]] = None,
        api_key_verifier: Optional[ApiKeyVerifier] = None,
        mtls_mapper: Optional[MtlsMapper] = None,
    ) -> None:
        self._core = _AuthCore(settings, policy, bearer_verifier, api_key_verifier, mtls_mapper)

    def intercept_service(self, continuation, handler_call_details):  # type: ignore[override]
        handler = continuation(handler_call_details)
        if handler is None:
            return None

        method = handler_call_details.method

        def _wrap_unary_unary(uu):
            def inner(request, context: grpc.ServicerContext):
                try:
                    principal, req_id = self._core.authenticate_and_authorize(
                        method,
                        handler_call_details.invocation_metadata,  # type: ignore
                        _peer_auth_md(context),
                    )
                    _principal_token = _principal_ctx.set(principal)  # principal может быть None для открытых методов
                    try:
                        _set_header_request_id(context, req_id)
                        return uu(request, context)
                    finally:
                        _principal_ctx.reset(_principal_token)
                except AuthError as e:
                    _abort_unauthenticated(context, str(e))
                except AuthorizationError as e:
                    _abort_permission_denied(context, str(e))
            return inner

        def _wrap_unary_stream(us):
            def inner(request, context: grpc.ServicerContext):
                try:
                    principal, req_id = self._core.authenticate_and_authorize(
                        method,
                        handler_call_details.invocation_metadata,  # type: ignore
                        _peer_auth_md(context),
                    )
                    _principal_token = _principal_ctx.set(principal)
                    try:
                        _set_header_request_id(context, req_id)
                        yield from us(request, context)
                    finally:
                        _principal_ctx.reset(_principal_token)
                except AuthError as e:
                    _abort_unauthenticated(context, str(e))
                except AuthorizationError as e:
                    _abort_permission_denied(context, str(e))
            return inner

        def _wrap_stream_unary(su):
            def inner(request_iter, context: grpc.ServicerContext):
                try:
                    principal, req_id = self._core.authenticate_and_authorize(
                        method,
                        handler_call_details.invocation_metadata,  # type: ignore
                        _peer_auth_md(context),
                    )
                    _principal_token = _principal_ctx.set(principal)
                    try:
                        _set_header_request_id(context, req_id)
                        return su(request_iter, context)
                    finally:
                        _principal_ctx.reset(_principal_token)
                except AuthError as e:
                    _abort_unauthenticated(context, str(e))
                except AuthorizationError as e:
                    _abort_permission_denied(context, str(e))
            return inner

        def _wrap_stream_stream(ss):
            def inner(request_iter, context: grpc.ServicerContext):
                try:
                    principal, req_id = self._core.authenticate_and_authorize(
                        method,
                        handler_call_details.invocation_metadata,  # type: ignore
                        _peer_auth_md(context),
                    )
                    _principal_token = _principal_ctx.set(principal)
                    try:
                        _set_header_request_id(context, req_id)
                        yield from ss(request_iter, context)
                    finally:
                        _principal_ctx.reset(_principal_token)
                except AuthError as e:
                    _abort_unauthenticated(context, str(e))
                except AuthorizationError as e:
                    _abort_permission_denied(context, str(e))
            return inner

        # Оборачиваем доступные хендлеры
        return grpc.method_handlers_generic_handler(
            handler_call_details.method.split("/")[1] if "/" in handler_call_details.method else "",  # service name hint
            {
                k: grpc.unary_unary_rpc_method_handler(_wrap_unary_unary(v.unary_unary))
                if k == "unary_unary" and v.unary_unary
                else grpc.unary_stream_rpc_method_handler(_wrap_unary_stream(v.unary_stream))
                if k == "unary_stream" and v.unary_stream
                else grpc.stream_unary_rpc_method_handler(_wrap_stream_unary(v.stream_unary))
                if k == "stream_unary" and v.stream_unary
                else grpc.stream_stream_rpc_method_handler(_wrap_stream_stream(v.stream_stream))
                if k == "stream_stream" and v.stream_stream
                else getattr(handler, k)
                for k, v in {
                    "unary_unary": handler,
                    "unary_stream": handler,
                    "stream_unary": handler,
                    "stream_stream": handler,
                }.items()
            },
        )

# ==============================================================================
# Async перехватчик (grpc.aio.ServerInterceptor)
# ==============================================================================

class AsyncAuthInterceptor(grpc_aio.ServerInterceptor):  # type: ignore[misc]
    """
    Пример подключения (grpc.aio):
        server = grpc.aio.server(interceptors=[
            AsyncAuthInterceptor(settings, policy, bearer_verifier=my_jwt, api_key_verifier=my_keys, mtls_mapper=my_mtls)
        ])
    """
    def __init__(
        self,
        settings: AuthSettings,
        policy: AuthPolicy,
        bearer_verifier: Optional[Union[BearerVerifier, VerifyBearerFn]] = None,
        api_key_verifier: Optional[ApiKeyVerifier] = None,
        mtls_mapper: Optional[MtlsMapper] = None,
    ) -> None:
        if grpc_aio is None:  # pragma: no cover
            raise RuntimeError("grpc.aio is not available")
        self._core = _AuthCore(settings, policy, bearer_verifier, api_key_verifier, mtls_mapper)

    async def intercept_service(self, continuation, handler_call_details):  # type: ignore[override]
        handler = await continuation(handler_call_details)
        if handler is None:
            return None

        method = handler_call_details.method

        async def _wrap_unary_unary(uu):
            async def inner(request, context: grpc_aio.ServicerContext):
                try:
                    principal, req_id = self._core.authenticate_and_authorize(
                        method,
                        handler_call_details.invocation_metadata,  # type: ignore
                        _peer_auth_md(context),
                    )
                    _principal_token = _principal_ctx.set(principal)
                    try:
                        _set_header_request_id(context, req_id)
                        return await uu(request, context)
                    finally:
                        _principal_ctx.reset(_principal_token)
                except AuthError as e:
                    await _abort_unauthenticated_async(context, str(e))
                except AuthorizationError as e:
                    await _abort_permission_denied_async(context, str(e))
            return inner

        async def _wrap_unary_stream(us):
            async def inner(request, context: grpc_aio.ServicerContext):
                try:
                    principal, req_id = self._core.authenticate_and_authorize(
                        method,
                        handler_call_details.invocation_metadata,  # type: ignore
                        _peer_auth_md(context),
                    )
                    _principal_token = _principal_ctx.set(principal)
                    try:
                        _set_header_request_id(context, req_id)
                        async for resp in us(request, context):
                            yield resp
                    finally:
                        _principal_ctx.reset(_principal_token)
                except AuthError as e:
                    await _abort_unauthenticated_async(context, str(e))
                except AuthorizationError as e:
                    await _abort_permission_denied_async(context, str(e))
            return inner

        async def _wrap_stream_unary(su):
            async def inner(request_iter, context: grpc_aio.ServicerContext):
                try:
                    principal, req_id = self._core.authenticate_and_authorize(
                        method,
                        handler_call_details.invocation_metadata,  # type: ignore
                        _peer_auth_md(context),
                    )
                    _principal_token = _principal_ctx.set(principal)
                    try:
                        _set_header_request_id(context, req_id)
                        return await su(request_iter, context)
                    finally:
                        _principal_ctx.reset(_principal_token)
                except AuthError as e:
                    await _abort_unauthenticated_async(context, str(e))
                except AuthorizationError as e:
                    await _abort_permission_denied_async(context, str(e))
            return inner

        async def _wrap_stream_stream(ss):
            async def inner(request_iter, context: grpc_aio.ServicerContext):
                try:
                    principal, req_id = self._core.authenticate_and_authorize(
                        method,
                        handler_call_details.invocation_metadata,  # type: ignore
                        _peer_auth_md(context),
                    )
                    _principal_token = _principal_ctx.set(principal)
                    try:
                        _set_header_request_id(context, req_id)
                        async for resp in ss(request_iter, context):
                            yield resp
                    finally:
                        _principal_ctx.reset(_principal_token)
                except AuthError as e:
                    await _abort_unauthenticated_async(context, str(e))
                except AuthorizationError as e:
                    await _abort_permission_denied_async(context, str(e))
            return inner

        return grpc_aio._create_servicer_handler(  # type: ignore[attr-defined]
            method,
            handler,
            _wrap_unary_unary,
            _wrap_unary_stream,
            _wrap_stream_unary,
            _wrap_stream_stream,
        )

# ==============================================================================
# Утилиты: peer auth context, метаданные, abort
# ==============================================================================

def _peer_auth_md(context: Union[grpc.ServicerContext, Any]) -> Mapping[str, str]:
    """
    Извлекает аутентификационные сведения пира (например, поля TLS).
    Содержимое зависит от настроек канала; при отсутствии возвращает пустой dict.
    """
    md: Dict[str, str] = {}
    try:
        auth_ctx = context.auth_context()  # type: ignore[attr-defined]
        # auth_ctx: Dict[str, Tuple[List[bytes], ...]]
        for k, v in auth_ctx.items():
            # Берём только первое значение; ключи приводим к str
            if not v:
                continue
            md[str(k)] = v[0].decode("utf-8", errors="ignore")
    except Exception:
        pass
    return md

def _set_header_request_id(context: Union[grpc.ServicerContext, Any], req_id: str) -> None:
    try:
        context.set_trailing_metadata((("x-request-id", req_id),))
    except Exception:
        pass

def _abort_unauthenticated(context: grpc.ServicerContext, detail: str) -> None:
    context.abort(grpc.StatusCode.UNAUTHENTICATED, detail)

def _abort_permission_denied(context: grpc.ServicerContext, detail: str) -> None:
    context.abort(grpc.StatusCode.PERMISSION_DENIED, detail)

async def _abort_unauthenticated_async(context: Any, detail: str) -> None:
    await context.abort(grpc.StatusCode.UNAUTHENTICATED, detail)  # type: ignore

async def _abort_permission_denied_async(context: Any, detail: str) -> None:
    await context.abort(grpc.StatusCode.PERMISSION_DENIED, detail)  # type: ignore

# ==============================================================================
# Пример интеграции Bearer JWT (опционально)
# ==============================================================================

class PyJWTBearerVerifier(BearerVerifier):  # pragma: no cover - пример
    """
    Пример интеграции с pyjwt/jwks. Зависимости умышленно не импортируются здесь.
    Реализуйте verify() с валидацией подписи, issuer, audience и пр.,
    верните Principal(scopes=set(claims.get("scope","").split()), roles=...).
    """
    def __init__(self, verify_fn: VerifyBearerFn) -> None:
        self._fn = verify_fn

    def verify(self, token: str, headers: Mapping[str, str]) -> Principal:
        return self._fn(token, headers)

# ==============================================================================
# Конфигурация по умолчанию (может быть переопределена при инициализации)
# ==============================================================================

DEFAULT_POLICY = AuthPolicy(
    allow_unauthenticated=("*/Health/*", "*/Info/*"),
    required_scopes={
        # Пример: для методов записи требуем scope
        "*/*:Create*": {"neuroforge.write"},
        "*/*:Update*": {"neuroforge.write"},
        "*/*:Delete*": {"neuroforge.write"},
    },
    required_roles={},
    require_all_roles=False,
)

DEFAULT_SETTINGS = AuthSettings()
