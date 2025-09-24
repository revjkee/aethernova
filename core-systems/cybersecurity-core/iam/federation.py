# cybersecurity-core/cybersecurity/iam/federation.py
from __future__ import annotations

"""
Федерация удостоверений (OIDC/JWT) для cybersecurity-core.

Возможности:
- Поддержка нескольких issuers (multi-tenant) с индивидуальными audience/algorithms
- OIDC Discovery -> jwks_uri; кэш JWKS с TTL и поддержкой ETag/If-None-Match
- Криптобэкенд: PyJWT или python-jose (автовыбор). Запрет alg="none".
- Валидация iss/aud/exp/nbf/iat, kid/alg соответствия ключу
- Маппинг ролей/скоупов из разных провайдеров (scope/scp, roles, realm_access, resource_access, groups)
- FastAPI dependency: проверка Bearer, опциональный список требуемых скоупов
- Метрики (в памяти) и простое здоровье
"""

import asyncio
import base64
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from functools import cached_property
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union
from uuid import UUID, uuid4

import httpx
from pydantic import BaseModel, Field, HttpUrl, ValidationError, field_validator

try:
    # Предпочтительно PyJWT
    import jwt as pyjwt  # type: ignore
    from jwt import algorithms as pyjwt_algorithms  # type: ignore
    _HAS_PYJWT = True
except Exception:  # pragma: no cover
    _HAS_PYJWT = False

try:
    # Фоллбек: python-jose
    from jose import jwt as jose_jwt  # type: ignore
    from jose.exceptions import JOSEError  # type: ignore
    _HAS_JOSE = True
except Exception:  # pragma: no cover
    _HAS_JOSE = False

logger = logging.getLogger(__name__)


# =====================================================================================
# Конфигурация федерации
# =====================================================================================

class IssuerConfig(BaseModel):
    """
    Конфиг конкретного Issuer'а.
    """
    issuer: HttpUrl
    audiences: List[str] = Field(default_factory=list)
    jwks_uri: Optional[HttpUrl] = None
    algorithms: List[str] = Field(default_factory=lambda: ["RS256", "ES256"])
    cache_ttl_sec: int = 3600
    leeway_sec: int = 60

    @field_validator("audiences", "algorithms", mode="before")
    @classmethod
    def _split_csv(cls, v: Any) -> Any:
        if v is None:
            return []
        if isinstance(v, str):
            parts = [p.strip() for p in v.replace(",", " ").split() if p.strip()]
            return parts
        return v


class FederationConfig(BaseModel):
    """
    Верхнеуровневый конфиг федерации.
    """
    issuers: List[IssuerConfig]
    enforce_known_issuers: bool = True
    http_timeout_sec: float = 3.0
    http_retries: int = 2
    http_proxy: Optional[str] = None


# =====================================================================================
# Модели результата валидации
# =====================================================================================

class VerifiedPrincipal(BaseModel):
    subject: str
    issuer: HttpUrl
    token_id: Optional[str] = None
    issued_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    audience: List[str] = Field(default_factory=list)
    email: Optional[str] = None
    name: Optional[str] = None
    tenant: Optional[str] = None
    scopes: List[str] = Field(default_factory=list)
    roles: List[str] = Field(default_factory=list)
    groups: List[str] = Field(default_factory=list)
    raw_claims: Dict[str, Any] = Field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        return self.expires_at is not None and datetime.now(timezone.utc) >= self.expires_at


# =====================================================================================
# Исключения
# =====================================================================================

class FederationError(Exception):
    pass


class TokenRejected(FederationError):
    def __init__(self, reason: str, *, status_code: int = 401) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status_code = status_code


# =====================================================================================
# JWKS Cache + OIDC Discovery
# =====================================================================================

@dataclass(slots=True)
class _JwksEntry:
    keys: Dict[str, Dict[str, Any]]  # kid -> JWK
    etag: Optional[str]
    expires_at: float


class JwksProvider:
    """
    Кэш JWKS по issuer: TTL + ETag/If-None-Match.
    """
    def __init__(self, cfg: FederationConfig) -> None:
        self.cfg = cfg
        self._jwks_cache: Dict[str, _JwksEntry] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        self._discovery_cache: Dict[str, Tuple[str, float]] = {}  # issuer -> (jwks_uri, expires_at)

    def _lock(self, issuer: str) -> asyncio.Lock:
        if issuer not in self._locks:
            self._locks[issuer] = asyncio.Lock()
        return self._locks[issuer]

    def _issuer_cfg(self, issuer: str) -> IssuerConfig:
        for ic in self.cfg.issuers:
            if str(ic.issuer).rstrip("/") == str(issuer).rstrip("/"):
                return ic
        raise TokenRejected("Unknown issuer", status_code=401)

    async def _http_client(self) -> httpx.AsyncClient:
        limits = httpx.Limits(max_keepalive_connections=20, max_connections=100)
        transport = httpx.AsyncHTTPTransport(retries=self.cfg.http_retries)
        proxies = self.cfg.http_proxy or None
        return httpx.AsyncClient(
            timeout=self.cfg.http_timeout_sec,
            limits=limits,
            transport=transport,
            proxies=proxies,
            headers={"User-Agent": "cybersecurity-core/iam-federation"},
        )

    async def _discover(self, issuer: str) -> str:
        """
        OIDC Discovery для получения jwks_uri. Кешируется.
        """
        now = time.time()
        cached = self._discovery_cache.get(issuer)
        if cached and cached[1] > now:
            return cached[0]

        ic = self._issuer_cfg(issuer)
        if ic.jwks_uri:
            jwks_uri = str(ic.jwks_uri)
            # кэшируем на TTL
            self._discovery_cache[issuer] = (jwks_uri, now + ic.cache_ttl_sec)
            return jwks_uri

        well_known = f"{str(issuer).rstrip('/')}/.well-known/openid-configuration"
        async with await self._http_client() as client:
            r = await client.get(well_known)
            if r.status_code != 200:
                raise TokenRejected(f"OIDC discovery failed: {r.status_code}", status_code=401)
            data = r.json()
            jwks_uri = data.get("jwks_uri")
            if not jwks_uri:
                raise TokenRejected("No jwks_uri in discovery", status_code=401)
            self._discovery_cache[issuer] = (jwks_uri, now + ic.cache_ttl_sec)
            return jwks_uri

    async def get_jwks(self, issuer: str, *, force_refresh: bool = False) -> Dict[str, Dict[str, Any]]:
        """
        Возвращает словарь kid -> JWK.
        """
        ic = self._issuer_cfg(issuer)
        now = time.time()

        async with self._lock(issuer):
            entry = self._jwks_cache.get(issuer)
            if entry and entry.expires_at > now and not force_refresh:
                return entry.keys

            jwks_uri = await self._discover(issuer)
            headers: Dict[str, str] = {}
            if entry and entry.etag:
                headers["If-None-Match"] = entry.etag

            async with await self._http_client() as client:
                resp = await client.get(jwks_uri, headers=headers)
                if resp.status_code == 304 and entry:
                    # продлеваем TTL
                    entry.expires_at = now + ic.cache_ttl_sec
                    return entry.keys
                if resp.status_code != 200:
                    raise TokenRejected(f"JWKS fetch error: {resp.status_code}", status_code=401)

                etag = resp.headers.get("ETag")
                payload = resp.json()
                keys = payload.get("keys") or []
                kid_map: Dict[str, Dict[str, Any]] = {}
                for k in keys:
                    kid = k.get("kid")
                    if not kid:
                        # допускаем ключ без kid — создаём детерминированный хэш по материалу
                        kid = self._fallback_kid(k)
                        k["kid"] = kid
                    kid_map[kid] = k

                self._jwks_cache[issuer] = _JwksEntry(keys=kid_map, etag=etag, expires_at=now + ic.cache_ttl_sec)
                return kid_map

    @staticmethod
    def _fallback_kid(jwk: Mapping[str, Any]) -> str:
        # Для RSA/EC вычислим kid как base64url(SHA256(нормализованной части))
        material = json.dumps(jwk, sort_keys=True, separators=(",", ":")).encode("utf-8")
        import hashlib
        digest = hashlib.sha256(material).digest()
        return base64.urlsafe_b64encode(digest)[:16].decode("ascii")


# =====================================================================================
# Криптобэкенды
# =====================================================================================

class _CryptoBackend:
    def verify(self, token: str, key: Dict[str, Any], algorithms: Sequence[str], audience: Sequence[str], issuer: str, leeway: int) -> Dict[str, Any]:
        raise NotImplementedError

    @staticmethod
    def header(token: str) -> Dict[str, Any]:
        # Без декодирования полезной нагрузки
        b64 = token.split(".")[0]
        # padding
        pad = "=" * (-len(b64) % 4)
        data = base64.urlsafe_b64decode(b64 + pad)
        return json.loads(data.decode("utf-8"))


class _PyJwtBackend(_CryptoBackend):
    def verify(self, token: str, key: Dict[str, Any], algorithms: Sequence[str], audience: Sequence[str], issuer: str, leeway: int) -> Dict[str, Any]:
        if not _HAS_PYJWT:
            raise TokenRejected("PyJWT not available", status_code=500)
        # Преобразуем JWK -> PEM
        public_key = pyjwt_algorithms.RSAAlgorithm.from_jwk(json.dumps(key)) if key.get("kty") == "RSA" else pyjwt_algorithms.ECAlgorithm.from_jwk(json.dumps(key))
        options = {"verify_signature": True, "verify_aud": bool(audience)}
        return pyjwt.decode(
            token,
            key=public_key,
            algorithms=list(algorithms),
            audience=list(audience) if audience else None,
            issuer=issuer,
            leeway=leeway,
            options=options,
        )


class _JoseBackend(_CryptoBackend):
    def verify(self, token: str, key: Dict[str, Any], algorithms: Sequence[str], audience: Sequence[str], issuer: str, leeway: int) -> Dict[str, Any]:
        if not _HAS_JOSE:
            raise TokenRejected("python-jose not available", status_code=500)
        try:
            return jose_jwt.decode(
                token,
                key,
                algorithms=list(algorithms),
                audience=list(audience) if audience else None,
                issuer=issuer,
                options={"verify_aud": bool(audience)},
                leeway=leeway,
            )
        except JOSEError as e:  # pragma: no cover
            raise TokenRejected(f"JWT verify failed: {e}", status_code=401) from e


def _select_backend() -> _CryptoBackend:
    if _HAS_PYJWT:
        return _PyJwtBackend()
    if _HAS_JOSE:
        return _JoseBackend()
    raise TokenRejected("No crypto backend available (install PyJWT or python-jose)", status_code=500)


# =====================================================================================
# Валидатор токенов
# =====================================================================================

class TokenValidator:
    def __init__(self, fed_cfg: FederationConfig) -> None:
        self.cfg = fed_cfg
        self.jwks = JwksProvider(fed_cfg)
        self.crypto = _select_backend()

    def _issuer_conf(self, issuer: str) -> IssuerConfig:
        issuer = str(issuer).rstrip("/")
        for ic in self.cfg.issuers:
            if str(ic.issuer).rstrip("/") == issuer:
                return ic
        if self.cfg.enforce_known_issuers:
            raise TokenRejected("Unknown issuer", status_code=401)
        # Дефолт с жёсткими настройками
        return IssuerConfig(issuer=issuer)  # type: ignore[arg-type]

    async def verify_bearer(self, token: str) -> VerifiedPrincipal:
        """
        Полная валидация Bearer JWT.
        """
        if token.count(".") != 2:
            raise TokenRejected("Not a JWT", status_code=401)

        # Заголовок: kid/alg
        hdr = self.crypto.header(token)
        alg = hdr.get("alg")
        if not alg or alg.lower() == "none":
            raise TokenRejected("Invalid alg", status_code=401)
        kid = hdr.get("kid")

        # Небезопасно, но читаем iss без проверки подписи чтобы выбрать конфиг/keys
        try:
            payload_unverified = self._unsafe_payload(token)
            iss = payload_unverified.get("iss")
            if not iss:
                raise TokenRejected("Missing iss", status_code=401)
        except Exception:
            # На случай брутально некорректного токена
            raise TokenRejected("Malformed token", status_code=401)

        ic = self._issuer_conf(iss)
        if alg not in ic.algorithms:
            raise TokenRejected("Algorithm not allowed", status_code=401)

        keys = await self.jwks.get_jwks(iss)
        key = None
        if kid and kid in keys:
            key = keys[kid]
        else:
            # fallback: единственный ключ или совпадение по alg/use
            for k in keys.values():
                if (not kid) and (k.get("alg") in (alg, None)) and (k.get("use") in ("sig", None)):
                    key = k
                    break
        if not key:
            # попробуем refresh (ротация ключей)
            keys = await self.jwks.get_jwks(iss, force_refresh=True)
            if kid and kid in keys:
                key = keys[kid]
            else:
                raise TokenRejected("Signing key not found", status_code=401)

        # Полная криптовалидация и проверка aud/iss/exp
        try:
            claims = self.crypto.verify(
                token=token,
                key=key,
                algorithms=ic.algorithms,
                audience=ic.audiences,
                issuer=str(ic.issuer),
                leeway=ic.leeway_sec,
            )
        except TokenRejected:
            raise
        except Exception as e:
            raise TokenRejected(f"Token verification failed: {e}", status_code=401) from e

        principal = self._map_principal(claims)
        # Дополнительные контроли
        if principal.is_expired:
            raise TokenRejected("Token expired", status_code=401)
        if ic.audiences and not set(principal.audience).intersection(ic.audiences):
            # допускаем azp как aud-замену в некоторых провайдерах
            azp = claims.get("azp")
            if not azp or azp not in ic.audiences:
                raise TokenRejected("Audience mismatch", status_code=401)
        return principal

    @staticmethod
    def _unsafe_payload(token: str) -> Dict[str, Any]:
        b64 = token.split(".")[1]
        pad = "=" * (-len(b64) % 4)
        data = base64.urlsafe_b64decode(b64 + pad)
        return json.loads(data.decode("utf-8"))

    @staticmethod
    def _to_dt(seconds: Optional[int]) -> Optional[datetime]:
        if not seconds:
            return None
        return datetime.fromtimestamp(seconds, tz=timezone.utc)

    def _map_principal(self, claims: Mapping[str, Any]) -> VerifiedPrincipal:
        # aud может быть строкой или списком
        aud = claims.get("aud")
        audience: List[str] = []
        if isinstance(aud, str):
            audience = [aud]
        elif isinstance(aud, (list, tuple)):
            audience = [str(a) for a in aud]

        # scope/scp
        scopes: List[str] = []
        if isinstance(claims.get("scope"), str):
            scopes = [s for s in claims["scope"].split() if s]
        elif isinstance(claims.get("scp"), (list, tuple)):
            scopes = [str(s) for s in claims["scp"]]

        # roles (Keycloak/Okta/Entra)
        roles: List[str] = []
        if isinstance(claims.get("roles"), (list, tuple)):
            roles.extend([str(r) for r in claims["roles"]])
        # Keycloak: realm_access.roles
        realm_access = claims.get("realm_access") or {}
        if isinstance(realm_access.get("roles"), (list, tuple)):
            roles.extend([str(r) for r in realm_access["roles"]])
        # Keycloak: resource_access.{client}.roles
        res_acc = claims.get("resource_access") or {}
        if isinstance(res_acc, dict):
            for v in res_acc.values():
                if isinstance(v, dict) and isinstance(v.get("roles"), (list, tuple)):
                    roles.extend([str(r) for r in v["roles"]])
        # Okta/Entra groups
        groups: List[str] = []
        if isinstance(claims.get("groups"), (list, tuple)):
            groups.extend([str(g) for g in claims["groups"]])

        subject = str(claims.get("sub"))
        tenant = claims.get("tid") or claims.get("tenant") or None
        principal = VerifiedPrincipal(
            subject=subject,
            issuer=str(claims.get("iss")),
            token_id=claims.get("jti"),
            issued_at=self._to_dt(claims.get("iat")),
            expires_at=self._to_dt(claims.get("exp")),
            audience=audience,
            email=claims.get("email"),
            name=claims.get("name") or claims.get("preferred_username"),
            tenant=str(tenant) if tenant else None,
            scopes=sorted(set(scopes)),
            roles=sorted(set(roles)),
            groups=sorted(set(groups)),
            raw_claims=dict(claims),
        )
        return principal


# =====================================================================================
# FastAPI dependency
# =====================================================================================

# Этот модуль не требует FastAPI для импорта, но предоставляет helper-функции.
try:
    from fastapi import Depends, Header, HTTPException, status
except Exception:  # pragma: no cover
    Depends = object  # type: ignore
    Header = object   # type: ignore
    HTTPException = Exception  # type: ignore
    status = type("status", (), {"HTTP_401_UNAUTHORIZED": 401, "HTTP_403_FORBIDDEN": 403, "HTTP_500_INTERNAL_SERVER_ERROR": 500})

class Federation:
    """
    Высокоуровневый фасад: создаёт валидатор и предоставляет зависимости.
    """
    def __init__(self, cfg: FederationConfig) -> None:
        self.validator = TokenValidator(cfg)

    async def require_principal(
        self,
        authorization: Optional[str] = Header(default=None, alias="Authorization"),
        required_scopes: Optional[Iterable[str]] = None,
    ) -> VerifiedPrincipal:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Missing Bearer token")
        token = authorization.split(" ", 1)[1].strip()
        try:
            principal = await self.validator.verify_bearer(token)
        except TokenRejected as e:
            raise HTTPException(e.status_code, detail=e.reason)
        except Exception as e:  # pragma: no cover
            logger.exception("Unexpected federation error: %s", e)
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Federation failure")

        if required_scopes:
            req = set(required_scopes)
            got = set(principal.scopes)
            if not req.issubset(got):
                raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Insufficient scopes")
        return principal

    # Метрики/здоровье
    async def health(self) -> Dict[str, Any]:
        # В продакшене можно добавить состояние кэша, сроки истечения и пр.
        return {"healthy": True}


# =====================================================================================
# Пример сборки конфигурации из settings.py (опционально)
# =====================================================================================

def from_app_settings() -> Federation:
    """
    Фабрика, читающая параметры из cybersecurity.settings.settings.security.
    Не делает жесткой зависимости, чтобы модуль можно было переиспользовать.
    """
    try:
        from cybersecurity.settings import settings as app_settings  # lazy import
    except Exception as e:  # pragma: no cover
        raise FederationError("Cannot import application settings") from e

    sec = app_settings.security  # type: ignore[attr-defined]
    # Если разрешён набор issuer'ов только один — собираем из него
    issuers: List[IssuerConfig] = []
    # Вариант 1: один из настроек
    if sec.issuer:
        issuers.append(IssuerConfig(
            issuer=str(sec.issuer),
            audiences=sec.audience or [],
            jwks_uri=str(sec.jwks_url) if sec.jwks_url else None,
            algorithms=sec.algorithms or ["RS256", "ES256"],
            cache_ttl_sec=3600,
            leeway_sec=sec.leeway_seconds or 60,
        ))
    # Можно расширить: загрузка из ENV/файла реестра здесь.

    if not issuers:
        raise FederationError("No issuers configured")

    fed_cfg = FederationConfig(
        issuers=issuers,
        enforce_known_issuers=True,
        http_timeout_sec=3.0,
        http_retries=2,
        http_proxy=None,
    )
    return Federation(fed_cfg)


# =====================================================================================
# Пример интеграции с FastAPI (документация, не исполняется самим модулем)
# =====================================================================================
# from fastapi import FastAPI, Depends
# fed = from_app_settings()
# app = FastAPI()
#
# @app.get("/v1/me")
# async def whoami(principal: VerifiedPrincipal = Depends(fed.require_principal)):
#     return {"sub": principal.subject, "scopes": principal.scopes, "roles": principal.roles}
#
# @app.get("/v1/secure")
# async def secure_endpoint(
#     principal: VerifiedPrincipal = Depends(lambda authorization=Header(..., alias="Authorization"): fed.require_principal(authorization, required_scopes=["policies:read"]))
# ):
#     return {"ok": True}
