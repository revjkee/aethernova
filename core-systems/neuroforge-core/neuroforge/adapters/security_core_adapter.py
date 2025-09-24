# file: neuroforge-core/neuroforge/adapters/security_core_adapter.py
from __future__ import annotations

import asyncio
import fnmatch
import hmac
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

logger = logging.getLogger(__name__)

# Опциональные зависимости (используются, если доступны)
try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

try:
    import jwt  # PyJWT  # type: ignore
except Exception:  # pragma: no cover
    jwt = None  # type: ignore


# =============================================================================
# Модели и исключения
# =============================================================================

@dataclass(frozen=True)
class Principal:
    subject: str
    tenant: Optional[str] = None
    roles: Tuple[str, ...] = tuple()
    scopes: Tuple[str, ...] = tuple()
    token_id: Optional[str] = None  # jti/sha256(api-key)/cert fingerprint
    issued_at: Optional[int] = None
    expires_at: Optional[int] = None
    auth_method: str = "unknown"  # bearer|api_key|mtls|unknown
    extra: Mapping[str, Any] = field(default_factory=dict)


class AuthError(Exception): ...
class AuthorizationError(Exception): ...
class ConfigError(Exception): ...
class UnavailableError(Exception): ...


# =============================================================================
# Конфигурация
# =============================================================================

@dataclass(frozen=True)
class JWKSConfig:
    url: str
    issuer: Optional[str] = None
    audience: Optional[str] = None
    algorithms: Tuple[str, ...] = ("RS256", "ES256", "EdDSA")
    cache_ttl_seconds: int = 300
    http_timeout_seconds: float = 3.0
    http_retries: int = 2


@dataclass(frozen=True)
class ApiKeyConfig:
    # Функция, возвращающая доступные ключи: id -> sha256_hex и атрибуты
    # Пример: {"key-1": {"sha256":"...", "roles":["svc"], "scopes":["neuroforge.read"]}}
    provider: Callable[[], Mapping[str, Mapping[str, Any]]]


@dataclass(frozen=True)
class MtlsConfig:
    enabled: bool = False
    # Маппер peer auth ctx -> Principal (например, по Subject/SAN)
    mapper: Optional[Callable[[Mapping[str, str]], Optional[Principal]]] = None


@dataclass(frozen=True)
class LocalPolicy:
    """
    Простая локальная политика (RBAC+scope) на основе шаблонов.
    patterns: список шаблонов "service/Method" или "resource:action"
    """
    allow_unauthenticated: Tuple[str, ...] = ("*/Health/*", "*/Info/*")
    required_scopes: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)
    required_roles: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)
    require_all_roles: bool = False


@dataclass(frozen=True)
class OPAConfig:
    url: Optional[str] = None              # например "http://opa:8181/v1/data/neuroforge/allow"
    timeout_seconds: float = 2.5
    retries: int = 1


@dataclass(frozen=True)
class AuditConfig:
    http_url: Optional[str] = None
    kafka_topic: Optional[str] = None
    kafka_conf: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class SecurityConfig:
    jwks: Optional[JWKSConfig] = None
    apikey: Optional[ApiKeyConfig] = None
    mtls: Optional[MtlsConfig] = None
    local_policy: LocalPolicy = field(default_factory=LocalPolicy)
    opa: OPAConfig = field(default_factory=OPAConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    cache_token_seconds: int = 60  # краткосрочный кэш валидации токена


# =============================================================================
# Утилиты и кэши
# =============================================================================

class _ExpiringCache:
    def __init__(self, ttl_seconds: int) -> None:
        self.ttl = max(0, ttl_seconds)
        self._data: Dict[str, Tuple[float, Any]] = {}

    def get(self, key: str) -> Optional[Any]:
        ent = self._data.get(key)
        if not ent:
            return None
        ts, val = ent
        if self.ttl and (time.time() - ts) > self.ttl:
            self._data.pop(key, None)
            return None
        return val

    def set(self, key: str, value: Any) -> None:
        self._data[key] = (time.time(), value)


class _JWKSCache:
    def __init__(self, cfg: JWKSConfig) -> None:
        self.cfg = cfg
        self._cache = _ExpiringCache(cfg.cache_ttl_seconds)

    async def get_jwks(self) -> Mapping[str, Any]:
        if not httpx:
            raise ConfigError("httpx is required for JWKS fetch")
        data = self._cache.get("jwks")
        if data is not None:
            return data
        # fetch with small retries
        last_err: Optional[Exception] = None
        for attempt in range(1, max(1, self.cfg.http_retries) + 1):
            try:
                async with httpx.AsyncClient(timeout=self.cfg.http_timeout_seconds) as cli:
                    r = await cli.get(self.cfg.url, headers={"Accept": "application/json"})
                    r.raise_for_status()
                    jwks = r.json()
                    if not isinstance(jwks, Mapping) or "keys" not in jwks:
                        raise UnavailableError("invalid JWKS payload")
                    self._cache.set("jwks", jwks)
                    return jwks
            except Exception as e:
                last_err = e
                if attempt >= self.cfg.http_retries:
                    break
                await asyncio.sleep(0.1 * attempt)
        raise UnavailableError(f"jwks fetch failed: {last_err}")


# =============================================================================
# Аудит: HTTP/Kafka sink (опционально активные)
# =============================================================================

class _AuditSink:
    def __init__(self, cfg: AuditConfig) -> None:
        self.cfg = cfg
        self._http_enabled = bool(cfg.http_url and httpx)
        self._kafka = None
        if cfg.kafka_topic:
            try:
                from confluent_kafka import Producer  # type: ignore
                self._kafka = Producer(dict(cfg.kafka_conf))
            except Exception:
                logger.warning("Kafka producer unavailable; audit->kafka disabled")

    async def emit(self, event: Mapping[str, Any]) -> None:
        if self._http_enabled:
            try:
                async with httpx.AsyncClient(timeout=2.0) as cli:  # type: ignore
                    await cli.post(self.cfg.http_url, json=dict(event))  # type: ignore
            except Exception as e:
                logger.debug("audit http error: %s", e)
        if self._kafka:
            try:
                self._kafka.produce(self.cfg.kafka_topic, json.dumps(event).encode("utf-8"))  # type: ignore
                self._kafka.poll(0)
            except Exception as e:
                logger.debug("audit kafka error: %s", e)


# =============================================================================
# Авторизация (локально или через OPA)
# =============================================================================

def _match_any(patterns: Iterable[str], value: str) -> bool:
    return any(fnmatch.fnmatch(value, p) for p in patterns)


def _authorize_local(
    principal: Principal,
    target: str,
    action: str,
    resource: str,
    policy: LocalPolicy,
) -> None:
    full = f"{target}:{action}"
    if _match_any(policy.allow_unauthenticated, target):
        return
    # scopes
    req_scopes: List[str] = []
    for patt, scopes in policy.required_scopes.items():
        if fnmatch.fnmatch(full, patt) or fnmatch.fnmatch(target, patt):
            req_scopes.extend(scopes)
    if req_scopes:
        if not set(req_scopes).issubset(set(principal.scopes)):
            need = ", ".join(sorted(set(req_scopes) - set(principal.scopes)))
            raise AuthorizationError(f"missing scopes: {need}")
    # roles
    req_roles: List[str] = []
    for patt, roles in policy.required_roles.items():
        if fnmatch.fnmatch(full, patt) or fnmatch.fnmatch(target, patt):
            req_roles.extend(roles)
    if req_roles:
        have = set(principal.roles)
        need = set(req_roles)
        if policy.require_all_roles:
            if not need.issubset(have):
                raise AuthorizationError(f"missing roles: {', '.join(sorted(need - have))}")
        else:
            if not (need & have):
                raise AuthorizationError(f"required any role: {', '.join(sorted(need))}")


async def _authorize_opa(
    principal: Principal,
    target: str,
    action: str,
    resource: str,
    context: Mapping[str, Any],
    cfg: OPAConfig,
) -> None:
    if not cfg.url:
        raise ConfigError("OPA url not configured")
    if not httpx:
        raise ConfigError("httpx is required for OPA")
    payload = {
        "input": {
            "principal": {
                "sub": principal.subject,
                "tenant": principal.tenant,
                "roles": list(principal.roles),
                "scopes": list(principal.scopes),
                "auth_method": principal.auth_method,
            },
            "target": target,
            "action": action,
            "resource": resource,
            "context": dict(context or {}),
        }
    }
    last_err: Optional[Exception] = None
    for attempt in range(1, max(1, cfg.retries) + 1):
        try:
            async with httpx.AsyncClient(timeout=cfg.timeout_seconds) as cli:  # type: ignore
                r = await cli.post(cfg.url, json=payload)  # type: ignore
                if r.status_code >= 400:
                    raise UnavailableError(f"opa http {r.status_code}")
                data = r.json()
                # Ожидаем форму: {"result":{"allow":true/false,"reason":"..."}}
                result = (data.get("result") or {})
                allow = bool(result.get("allow"))
                if not allow:
                    reason = result.get("reason") or "opa deny"
                    raise AuthorizationError(str(reason))
                return
        except AuthorizationError:
            raise
        except Exception as e:
            last_err = e
            if attempt >= cfg.retries:
                break
            await asyncio.sleep(0.05 * attempt)
    raise UnavailableError(f"opa error: {last_err}")


# =============================================================================
# SecurityCoreAdapter
# =============================================================================

class SecurityCoreAdapter:
    """
    Универсальный адаптер аутентификации/авторизации:
      - verify_bearer() -> Principal (JWT+JWKS)
      - verify_api_key() -> Principal
      - verify_mtls() -> Principal
      - authorize() -> None (или бросает AuthorizationError)
      - audit() -> emit audit event (лучше запускать fire-and-forget)
    """

    def __init__(self, cfg: SecurityConfig) -> None:
        self.cfg = cfg
        self._jwks = _JWKSCache(cfg.jwks) if cfg.jwks else None
        self._token_cache = _ExpiringCache(cfg.cache_token_seconds)
        self._audit = _AuditSink(cfg.audit)

        # Быстрая проверка конфигурации
        if not (cfg.jwks or cfg.apikey or (cfg.mtls and cfg.mtls.enabled)):
            raise ConfigError("At least one auth method must be configured (jwks/apikey/mtls)")

    # -------------------------- AUTHN --------------------------

    async def verify_bearer(self, token: str, headers: Mapping[str, str] | None = None) -> Principal:
        if not self._jwks:
            raise ConfigError("JWKS not configured")
        if not jwt:
            raise ConfigError("PyJWT is required for bearer verification")

        # Кэш на сигнатуру токена (sha256)
        sig = hashlib.sha256(token.encode("utf-8")).hexdigest()
        cached = self._token_cache.get(sig)
        if cached:
            return cached

        # Получаем заголовок и kid
        try:
            header = jwt.get_unverified_header(token)  # type: ignore[attr-defined]
        except Exception as e:
            raise AuthError(f"invalid jwt header: {e}")
        kid = header.get("kid")
        alg = header.get("alg")

        if self.cfg.jwks.algorithms and alg not in self.cfg.jwks.algorithms:
            raise AuthError(f"unsupported alg: {alg}")

        jwks = await self._jwks.get_jwks()
        # PyJWT умеет принимать ключ в JWK-формате с алгоритмом
        key = None
        for k in jwks.get("keys", []):
            if (kid and k.get("kid") == kid) or (not kid):
                key = k
                break
        if not key:
            raise UnavailableError("jwks key not found")

        options = {"verify_aud": self.cfg.jwks.audience is not None}
        try:
            claims = jwt.decode(  # type: ignore[attr-defined]
                token,
                key,
                algorithms=list(self.cfg.jwks.algorithms),
                audience=self.cfg.jwks.audience,
                issuer=self.cfg.jwks.issuer,
                options=options,
            )
        except Exception as e:
            raise AuthError(f"invalid jwt: {e}")

        princ = _principal_from_claims(claims, method="bearer")
        self._token_cache.set(sig, princ)
        return princ

    async def verify_api_key(self, raw_key: str, headers: Mapping[str, str] | None = None) -> Principal:
        if not self.cfg.apikey:
            raise ConfigError("API key verification not configured")
        store = self.cfg.apikey.provider() or {}
        # Форматы: "id.raw" или просто "raw"; поддержим оба.
        key_id, raw = _split_api_key(raw_key)
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        matched_id = None
        meta: Mapping[str, Any] = {}
        if key_id and key_id in store:
            if hmac.compare_digest(store[key_id].get("sha256", ""), digest):
                matched_id = key_id
                meta = store[key_id]
        else:
            # Поиск по значению (дорого, но безопаснее — константно-временное сравнение)
            for kid, rec in store.items():
                if hmac.compare_digest(rec.get("sha256", ""), digest):
                    matched_id = kid
                    meta = rec
                    break
        if not matched_id:
            raise AuthError("invalid api key")

        roles = tuple(meta.get("roles") or ())
        scopes = tuple(meta.get("scopes") or ())
        tenant = (headers or {}).get("x-tenant-id") or meta.get("tenant")
        princ = Principal(
            subject=f"api-key:{matched_id}",
            tenant=tenant,
            roles=tuple(roles),
            scopes=tuple(scopes),
            token_id=digest,
            auth_method="api_key",
            extra={"key_id": matched_id},
        )
        return princ

    async def verify_mtls(self, peer_auth_ctx: Mapping[str, str]) -> Principal:
        if not (self.cfg.mtls and self.cfg.mtls.enabled):
            raise ConfigError("mTLS not configured")
        if not self.cfg.mtls.mapper:
            raise ConfigError("mTLS mapper not provided")
        princ = self.cfg.mtls.mapper(peer_auth_ctx)
        if not princ:
            raise AuthError("invalid mtls identity")
        return princ

    # -------------------------- AUTHZ --------------------------

    async def authorize(
        self,
        principal: Principal,
        *,
        target: str,     # например "svc.UserService/Get"
        action: str,     # "read"|"write"|...
        resource: str,   # URI/идентификатор ресурса
        context: Mapping[str, Any] | None = None,
    ) -> None:
        # Попытка через OPA, если указан
        if self.cfg.opa.url:
            try:
                await _authorize_opa(principal, target, action, resource, context or {}, self.cfg.opa)
                return
            except UnavailableError as e:
                logger.debug("OPA unavailable, falling back to local policy: %s", e)
        # Локальная политика
        _authorize_local(principal, target, action, resource, self.cfg.local_policy)

    # -------------------------- AUDIT --------------------------

    async def audit(
        self,
        *,
        event_type: str,
        principal: Optional[Principal],
        target: str,
        action: str,
        resource: str,
        allowed: bool,
        request_id: Optional[str] = None,
        reason: Optional[str] = None,
        extras: Mapping[str, Any] | None = None,
    ) -> None:
        evt = {
            "type": event_type,
            "time": int(time.time() * 1000),
            "target": target,
            "action": action,
            "resource": resource,
            "allowed": allowed,
            "reason": reason,
            "request_id": request_id,
            "principal": {
                "sub": principal.subject if principal else None,
                "tenant": principal.tenant if principal else None,
                "roles": list(principal.roles) if principal else None,
                "scopes": list(principal.scopes) if principal else None,
                "auth_method": principal.auth_method if principal else None,
            },
            "extras": dict(extras or {}),
        }
        # Аудит — «мягкий»: ошибки не должны ронять запрос
        try:
            await self._audit.emit(evt)
        except Exception as e:
            logger.debug("audit emit error: %s", e)


# =============================================================================
# Вспомогательное
# =============================================================================

def _split_api_key(raw: str) -> Tuple[Optional[str], str]:
    """
    Поддержка формата "id.rawsecret". Если разделителя нет, возвращаем (None, raw).
    """
    if "." in raw:
        left, right = raw.split(".", 1)
        if left and right:
            return left, right
    return None, raw


def _principal_from_claims(claims: Mapping[str, Any], method: str) -> Principal:
    sub = str(claims.get("sub") or claims.get("client_id") or "unknown")
    tenant = claims.get("tenant") or claims.get("org") or claims.get("realm")
    roles = _extract_roles(claims)
    scopes = _extract_scopes(claims)
    jti = claims.get("jti")
    iat = claims.get("iat")
    exp = claims.get("exp")
    return Principal(
        subject=sub,
        tenant=str(tenant) if tenant is not None else None,
        roles=tuple(roles),
        scopes=tuple(scopes),
        token_id=str(jti) if jti is not None else None,
        issued_at=int(iat) if iat is not None else None,
        expires_at=int(exp) if exp is not None else None,
        auth_method=method,
        extra={k: v for k, v in claims.items() if k not in {"sub", "tenant", "org", "realm", "jti", "iat", "exp", "scope", "roles", "role"}},
    )


def _extract_scopes(claims: Mapping[str, Any]) -> List[str]:
    scope = claims.get("scope")
    if isinstance(scope, str):
        return [s for s in scope.split() if s]
    if isinstance(scope, list):
        return [str(s) for s in scope]
    return []


def _extract_roles(claims: Mapping[str, Any]) -> List[str]:
    # Популярные поля: "roles", "role", "realm_access": {"roles":[...]} (Keycloak)
    if "roles" in claims and isinstance(claims["roles"], list):
        return [str(r) for r in claims["roles"]]
    if "role" in claims and isinstance(claims["role"], (str, list)):
        v = claims["role"]
        return [str(v)] if isinstance(v, str) else [str(r) for r in v]
    ra = claims.get("realm_access")
    if isinstance(ra, Mapping) and isinstance(ra.get("roles"), list):
        return [str(r) for r in ra["roles"]]
    return []


# =============================================================================
# Пример использования (в комментариях)
# =============================================================================

"""
# Конфигурация:

cfg = SecurityConfig(
    jwks=JWKSConfig(
        url="https://issuer.example.com/.well-known/jwks.json",
        issuer="https://issuer.example.com/",
        audience="neuroforge-core",
    ),
    apikey=ApiKeyConfig(
        provider=lambda: {
            "svc-gateway": {"sha256": "<hex>", "roles": ["svc"], "scopes": ["neuroforge.read"]},
        }
    ),
    mtls=MtlsConfig(
        enabled=False,
        mapper=None,
    ),
    local_policy=LocalPolicy(
        allow_unauthenticated=("*/Health/*", "*/Info/*"),
        required_scopes={
            "*/*:Create*": ("neuroforge.write",),
            "*/*:Update*": ("neuroforge.write",),
            "*/*:Delete*": ("neuroforge.write",),
        },
        required_roles={},
        require_all_roles=False,
    ),
    opa=OPAConfig(
        url=None,  # при необходимости: "http://opa:8181/v1/data/neuroforge/allow"
        timeout_seconds=2.0,
        retries=1,
    ),
    audit=AuditConfig(
        http_url=None,
        kafka_topic=None,
    ),
)

adapter = SecurityCoreAdapter(cfg)

# Проверка Bearer:
principal = await adapter.verify_bearer(token, headers={"x-tenant-id": "acme"})

# Проверка API-ключа:
principal = await adapter.verify_api_key("svc-gateway.<raw>", headers={"x-tenant-id": "acme"})

# Авторизация:
await adapter.authorize(principal, target="svc.UserService/Get", action="read", resource="users:123")

# Аудит:
await adapter.audit(event_type="authz", principal=principal, target="svc.UserService/Get",
                    action="read", resource="users:123", allowed=True, request_id="...")

"""
