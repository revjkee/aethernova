# zero-trust-core/zero_trust/adapters/idp_adapter.py
# -*- coding: utf-8 -*-
"""
Промышленный адаптер IdP (OIDC/OAuth2) для Zero-Trust.

Возможности:
- Абстрактный интерфейс IdPAdapter и konkrete OIDCAdapter.
- .well-known discovery с TTL-кэшем, JWKS кэш и key rotation.
- Проверка токенов через OAuth2 Introspection (рекомендуется) ИЛИ локально через JWKS
  (опционально с PyJWT, если установлен).
- Обмен кода на токены (PKCE), refresh, userinfo, end session.
- Обработка backchannel logout (sid/jti), интеграция с RevocationService (если доступен).
- Маппинг claims → роли/атрибуты приложения, нормализация identity.
- Строгие таймауты, экспоненциальные ретраи с джиттером, структурированные логи
  с маскированием PII, безопасные дефолты.
- Мульти-IdP/тенант реестр.

Внешние зависимости: не требуются. Опционально: httpx, PyJWT.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import random
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple, Union, Callable

logger = logging.getLogger("zero_trust.idp")
logger.setLevel(logging.INFO)

# Опциональные зависимости
_HAS_HTTPX = False
try:  # pragma: no cover
    import httpx  # type: ignore
    _HAS_HTTPX = True
except Exception:  # pragma: no cover
    _HAS_HTTPX = False

_HAS_PYJWT = False
try:  # pragma: no cover
    import jwt as pyjwt  # type: ignore
    from jwt import algorithms as _jwt_algorithms  # type: ignore
    _HAS_PYJWT = True
except Exception:  # pragma: no cover
    _HAS_PYJWT = False

# Опциональная интеграция с сервисом отзыва
_HAS_REVOCATION = False
try:  # pragma: no cover
    from zero_trust.session.revocation import RevocationService, Reason, build_backend_from_env  # type: ignore
    _HAS_REVOCATION = True
except Exception:  # pragma: no cover
    _HAS_REVOCATION = False


# =============================================================================
# Утилиты
# =============================================================================

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def _now() -> int:
    return int(time.time())

def _clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))

def _redact(s: Optional[str], keep_right: int = 4) -> str:
    if not s:
        return ""
    return ("*" * max(len(s) - keep_right, 0)) + s[-keep_right:]

def _json_compact(d: Any) -> str:
    try:
        return json.dumps(d, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        return str(d)


# =============================================================================
# TTL Cache (простой и безопасный для корутин)
# =============================================================================

class TTLCache:
    def __init__(self, ttl_seconds: int = 300, max_size: int = 256):
        self.ttl = int(ttl_seconds)
        self.max = int(max_size)
        self._store: Dict[str, Tuple[int, Any]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            it = self._store.get(key)
            if not it:
                return None
            exp, val = it
            if exp < _now():
                self._store.pop(key, None)
                return None
            return val

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        async with self._lock:
            if len(self._store) >= self.max:
                # простая политика: удалить случайный элемент
                self._store.pop(next(iter(self._store)), None)
            self._store[key] = (_now() + int(ttl or self.ttl), value)

    async def clear(self) -> None:
        async with self._lock:
            self._store.clear()


# =============================================================================
# HTTP клиент (абстракция + реализации)
# =============================================================================

class AsyncHttpClient(ABC):
    @abstractmethod
    async def get(self, url: str, headers: Mapping[str, str] | None = None, timeout: float = 3.0) -> Tuple[int, Mapping[str, str], bytes]:
        ...

    @abstractmethod
    async def post(self, url: str, headers: Mapping[str, str] | None = None, data: Mapping[str, str] | None = None,
                   json_body: Any | None = None, timeout: float = 5.0) -> Tuple[int, Mapping[str, str], bytes]:
        ...

    @abstractmethod
    async def close(self) -> None:
        ...

class HttpxClient(AsyncHttpClient):
    def __init__(self):
        if not _HAS_HTTPX:
            raise RuntimeError("httpx not available")
        self._client = httpx.AsyncClient(follow_redirects=False, timeout=None)  # таймауты на вызовах

    async def get(self, url: str, headers: Mapping[str, str] | None = None, timeout: float = 3.0):
        r = await self._client.get(url, headers=headers, timeout=timeout)
        return r.status_code, dict(r.headers), r.content

    async def post(self, url: str, headers: Mapping[str, str] | None = None, data: Mapping[str, str] | None = None,
                   json_body: Any | None = None, timeout: float = 5.0):
        r = await self._client.post(url, headers=headers, data=data, json=json_body, timeout=timeout)
        return r.status_code, dict(r.headers), r.content

    async def close(self) -> None:
        await self._client.aclose()

class UrllibClient(AsyncHttpClient):
    """
    Без внешних зависимостей: оборачиваем синхронный urllib в to_thread.
    Для прод-нагрузок предпочтителен httpx.
    """
    def __init__(self):
        import urllib.request  # lazy
        self._u = __import__("urllib.request", fromlist=['request'])

    async def get(self, url: str, headers: Mapping[str, str] | None = None, timeout: float = 3.0):
        def _do():
            req = self._u.Request(url, headers=headers or {}, method="GET")
            with self._u.urlopen(req, timeout=timeout) as resp:
                return resp.getcode(), dict(resp.headers.items()), resp.read()
        return await asyncio.to_thread(_do)

    async def post(self, url: str, headers: Mapping[str, str] | None = None, data: Mapping[str, str] | None = None,
                   json_body: Any | None = None, timeout: float = 5.0):
        def _do():
            hdrs = {"content-type": "application/x-www-form-urlencoded"}
            if json_body is not None:
                hdrs = {"content-type": "application/json"}
                payload = json.dumps(json_body).encode("utf-8")
            else:
                payload = "&".join([f"{k}={v}" for k, v in (data or {}).items()]).encode("utf-8")
            if headers:
                hdrs.update(headers)
            req = self._u.Request(url, headers=hdrs, data=payload, method="POST")
            with self._u.urlopen(req, timeout=timeout) as resp:
                return resp.getcode(), dict(resp.headers.items()), resp.read()
        return await asyncio.to_thread(_do)

    async def close(self) -> None:
        return

def build_http_client() -> AsyncHttpClient:
    if _HAS_HTTPX:
        return HttpxClient()
    return UrllibClient()


# =============================================================================
# Конфиг/модели
# =============================================================================

@dataclass
class IdentityMapping:
    """
    Правила маппинга claims → роли/атрибуты приложения.
    """
    roles_claim: str = "roles"
    fallback_roles: List[str] = field(default_factory=list)
    # статический маппинг по значениям claim -> роли
    role_map: Dict[str, List[str]] = field(default_factory=dict)
    # фильтр аудитории (aud) и издателя (iss)
    expected_issuer: Optional[str] = None
    expected_audience: Optional[str] = None

    def map_roles(self, claims: Mapping[str, Any]) -> List[str]:
        roles: List[str] = []
        # 1) прямой массив в claims[roles_claim]
        v = claims.get(self.roles_claim)
        if isinstance(v, list):
            roles.extend([str(x) for x in v])
        elif isinstance(v, str) and v:
            roles.append(v)
        # 2) role_map по отдельному claim (например, realm_access.roles в Keycloak)
        for key, mapped in self.role_map.items():
            if key in claims:
                val = claims.get(key)
                if isinstance(val, str) and val in mapped:
                    roles.extend(mapped[val])
                elif isinstance(val, list):
                    for item in val:
                        if item in mapped:
                            roles.extend(mapped[item])
        if not roles and self.fallback_roles:
            roles.extend(self.fallback_roles)
        # нормализуем
        return sorted(set([r for r in roles if isinstance(r, str) and r]))

@dataclass
class IdPConfig:
    """
    Конфигурация IdP/OIDC.
    """
    issuer: str
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    # override endpoints (если discovery не используется/недоступен)
    jwks_uri: Optional[str] = None
    token_endpoint: Optional[str] = None
    userinfo_endpoint: Optional[str] = None
    introspection_endpoint: Optional[str] = None
    end_session_endpoint: Optional[str] = None

    # Поведение проверки токенов
    use_introspection: bool = True       # рекомендовано
    local_verify_if_possible: bool = True
    allowed_algs: List[str] = field(default_factory=lambda: ["RS256", "ES256", "EdDSA"])
    leeway_seconds: int = 60
    require_sub: bool = False

    # Кэш/таймауты/ретраи
    discovery_ttl: int = 3600
    jwks_ttl: int = 1800
    http_timeout_s: float = 3.0
    retries: int = 2
    backoff_base_s: float = 0.2
    backoff_max_s: float = 1.5

    # PKCE / audience
    default_scopes: List[str] = field(default_factory=lambda: ["openid", "profile", "email"])
    audience: Optional[str] = None

    # Маппинг identity
    mapping: IdentityMapping = field(default_factory=IdentityMapping)

    # Дополнительно
    name: str = "default"

@dataclass
class TokenResponse:
    access_token: str
    id_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: str = "Bearer"
    expires_in: int = 3600
    scope: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

@dataclass
class IntrospectionResult:
    active: bool
    sub: Optional[str] = None
    scope: Optional[str] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    iss: Optional[str] = None
    aud: Optional[Union[str, List[str]]] = None
    client_id: Optional[str] = None
    username: Optional[str] = None
    token_type: Optional[str] = None
    jti: Optional[str] = None
    sid: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Интерфейс адаптера
# =============================================================================

class IdPAdapter(ABC):
    @abstractmethod
    async def verify_access_token(self, token: str) -> Mapping[str, Any]:
        """Проверка и декодирование access token. Возвращает claims при успехе, иначе бросает исключение."""
        ...

    @abstractmethod
    async def get_userinfo(self, access_token: str) -> Mapping[str, Any]:
        ...

    @abstractmethod
    async def exchange_code(self, code: str, redirect_uri: str, code_verifier: Optional[str] = None,
                            extra: Optional[Mapping[str, str]] = None) -> TokenResponse:
        ...

    @abstractmethod
    async def refresh(self, refresh_token: str, extra: Optional[Mapping[str, str]] = None) -> TokenResponse:
        ...

    @abstractmethod
    async def end_session(self, id_token_hint: Optional[str] = None, post_logout_redirect_uri: Optional[str] = None) -> bool:
        ...

    @abstractmethod
    async def handle_backchannel_logout(self, logout_token_jwt: str) -> bool:
        """Обработать backchannel logout (OIDC RP-Initiated). Возвращает True, если успешно."""
        ...

    @abstractmethod
    async def close(self) -> None:
        ...


# =============================================================================
# Реализация OIDC
# =============================================================================

class OIDCAdapter(IdPAdapter):
    def __init__(self, config: IdPConfig, http: Optional[AsyncHttpClient] = None,
                 revocation: Optional["RevocationService"] = None):
        self.cfg = config
        self.http = http or build_http_client()
        self.discovery_cache = TTLCache(ttl_seconds=config.discovery_ttl, max_size=64)
        self.jwks_cache = TTLCache(ttl_seconds=config.jwks_ttl, max_size=8)
        self.revocation = revocation  # может быть None
        self._discovery_key = f"discovery:{self.cfg.issuer}"
        self._jwks_key = f"jwks:{self.cfg.issuer}"

    # ---------------------------
    # Общие вспомогательные методы
    # ---------------------------

    def _discovery_url(self) -> str:
        iss = self.cfg.issuer.rstrip("/")
        return f"{iss}/.well-known/openid-configuration"

    async def _retry(self, fn: Callable[[], Any]) -> Any:
        last_exc = None
        for attempt in range(self.cfg.retries + 1):
            try:
                return await fn()
            except Exception as e:
                last_exc = e
                if attempt >= self.cfg.retries:
                    break
                backoff = _clamp(self.cfg.backoff_base_s * (2 ** attempt) + random.random() * 0.2,
                                 0, self.cfg.backoff_max_s)
                await asyncio.sleep(backoff)
        raise last_exc  # type: ignore

    async def _discover(self) -> Dict[str, Any]:
        cached = await self.discovery_cache.get(self._discovery_key)
        if cached:
            return cached
        async def _call():
            url = self._discovery_url()
            st, _h, body = await self.http.get(url, timeout=self.cfg.http_timeout_s)
            if st != 200:
                raise RuntimeError(f"discovery failed: {st}")
            data = json.loads(body.decode("utf-8"))
            await self.discovery_cache.set(self._discovery_key, data)
            return data
        return await self._retry(_call)

    async def _jwks(self) -> Dict[str, Any]:
        cached = await self.jwks_cache.get(self._jwks_key)
        if cached:
            return cached
        async def _call():
            jwks_uri = self.cfg.jwks_uri or (await self._discover()).get("jwks_uri")
            if not jwks_uri:
                raise RuntimeError("jwks_uri not available")
            st, _h, body = await self.http.get(jwks_uri, timeout=self.cfg.http_timeout_s)
            if st != 200:
                raise RuntimeError(f"jwks fetch failed: {st}")
            data = json.loads(body.decode("utf-8"))
            await self.jwks_cache.set(self._jwks_key, data)
            return data
        return await self._retry(_call)

    def _auth_header_basic(self) -> Dict[str, str]:
        if not self.cfg.client_id or not self.cfg.client_secret:
            return {}
        userpass = f"{self.cfg.client_id}:{self.cfg.client_secret}".encode("utf-8")
        return {"authorization": f"Basic {_b64u(userpass)}"}

    def _token_endpoint(self) -> str:
        return self.cfg.token_endpoint or (awaitable_value := None) or ""  # placeholder to satisfy type checker

    async def _token_endpoint_async(self) -> str:
        if self.cfg.token_endpoint:
            return self.cfg.token_endpoint
        d = await self._discover()
        te = d.get("token_endpoint")
        if not te:
            raise RuntimeError("token_endpoint not available")
        return te

    async def _userinfo_endpoint_async(self) -> str:
        if self.cfg.userinfo_endpoint:
            return self.cfg.userinfo_endpoint
        d = await self._discover()
        ue = d.get("userinfo_endpoint")
        if not ue:
            raise RuntimeError("userinfo_endpoint not available")
        return ue

    async def _introspection_endpoint_async(self) -> str:
        if self.cfg.introspection_endpoint:
            return self.cfg.introspection_endpoint
        d = await self._discover()
        ie = d.get("introspection_endpoint")
        if not ie:
            raise RuntimeError("introspection_endpoint not available")
        return ie

    async def _end_session_endpoint_async(self) -> Optional[str]:
        if self.cfg.end_session_endpoint:
            return self.cfg.end_session_endpoint
        d = await self._discover()
        return d.get("end_session_endpoint")

    # ---------------------------
    # Публичные методы адаптера
    # ---------------------------

    async def verify_access_token(self, token: str) -> Mapping[str, Any]:
        """
        Безопасная проверка access token.
        Приоритет:
        1) Introspection (если включён и доступен).
        2) Локальная проверка (если PyJWT и есть JWKS), с проверкой iss/aud/exp/iat/nbf.
        """
        token = token.strip()
        if not token:
            raise ValueError("empty token")

        # Introspection
        if self.cfg.use_introspection:
            try:
                res = await self._introspect(token)
                if res.active:
                    claims = dict(res.raw)
                    # нормализация критичных полей
                    if res.sub:
                        claims["sub"] = res.sub
                    if res.iss:
                        claims["iss"] = res.iss
                    if res.aud:
                        claims["aud"] = res.aud
                    self._validate_iss_aud(claims)
                    return claims
                raise RuntimeError("token inactive")
            except Exception as e:
                logger.info("Introspection failed (%s), fallback=%s", str(e), self.cfg.local_verify_if_possible)

        # Локальная проверка (если возможно)
        if self.cfg.local_verify_if_possible and _HAS_PYJWT:
            jwks = await self._jwks()
            try:
                jwk_client = pyjwt.PyJWKClient(jwks.get("jwks_uri", "") if hasattr(pyjwt, "PyJWKClient") else "")
            except Exception:
                jwk_client = None
            # Получим заголовок для kid
            try:
                headers = pyjwt.get_unverified_header(token)
                kid = headers.get("kid")
            except Exception as e:
                raise RuntimeError(f"invalid token header: {e}")

            key = None
            if jwk_client:
                try:
                    key = jwk_client.get_signing_key_from_jwt(token).key  # type: ignore
                except Exception:
                    key = None
            if key is None:
                # Попробуем вручную выбрать ключ из JWKS
                kset = jwks.get("keys", [])
                for k in kset:
                    if k.get("kid") == kid:
                        try:
                            alg = k.get("alg")
                            if alg and alg not in self.cfg.allowed_algs:
                                raise RuntimeError("alg not allowed")
                            # PyJWT сам преобразует JWK dict → ключ
                            key = pyjwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(k)) if k.get("kty") == "RSA" else pyjwt.algorithms.ECAlgorithm.from_jwk(json.dumps(k))  # type: ignore
                        except Exception:
                            key = None
                        break
            if key is None:
                raise RuntimeError("signing key not found")

            options = {"require": ["exp", "iat"], "verify_aud": bool(self.cfg.mapping.expected_audience or self.cfg.audience)}
            claims = pyjwt.decode(
                token,
                key=key,
                algorithms=self.cfg.allowed_algs,
                audience=self.cfg.mapping.expected_audience or self.cfg.audience,
                issuer=self.cfg.mapping.expected_issuer or self.cfg.issuer,
                leeway=self.cfg.leeway_seconds,
                options=options,
            )
            self._validate_sub_required(claims)
            return claims

        raise RuntimeError("token verification failed")

    async def get_userinfo(self, access_token: str) -> Mapping[str, Any]:
        url = await self._userinfo_endpoint_async()
        headers = {"authorization": f"Bearer {access_token}"}
        st, _h, body = await self.http.get(url, headers=headers, timeout=self.cfg.http_timeout_s)
        if st != 200:
            raise RuntimeError(f"userinfo failed: {st}")
        data = json.loads(body.decode("utf-8"))
        return data

    async def exchange_code(self, code: str, redirect_uri: str, code_verifier: Optional[str] = None,
                            extra: Optional[Mapping[str, str]] = None) -> TokenResponse:
        token_url = await self._token_endpoint_async()
        data: Dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self.cfg.client_id or "",
        }
        if self.cfg.client_secret:
            # Используем client_secret_basic если нет явного требования на post_body
            headers = self._auth_header_basic()
        else:
            headers = {}
        if code_verifier:
            data["code_verifier"] = code_verifier
        if self.cfg.audience:
            data["audience"] = self.cfg.audience
        if extra:
            data.update({str(k): str(v) for k, v in extra.items()})
        st, _h, body = await self.http.post(token_url, headers=headers, data=data, timeout=max(self.cfg.http_timeout_s, 5.0))
        if st != 200:
            raise RuntimeError(f"token exchange failed: {st}")
        payload = json.loads(body.decode("utf-8"))
        return TokenResponse(
            access_token=payload.get("access_token", ""),
            id_token=payload.get("id_token"),
            refresh_token=payload.get("refresh_token"),
            token_type=payload.get("token_type", "Bearer"),
            expires_in=int(payload.get("expires_in", 3600)),
            scope=payload.get("scope"),
            raw=payload
        )

    async def refresh(self, refresh_token: str, extra: Optional[Mapping[str, str]] = None) -> TokenResponse:
        token_url = await self._token_endpoint_async()
        data: Dict[str, str] = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.cfg.client_id or "",
        }
        if self.cfg.audience:
            data["audience"] = self.cfg.audience
        if extra:
            data.update({str(k): str(v) for k, v in extra.items()})
        headers = self._auth_header_basic()
        st, _h, body = await self.http.post(token_url, headers=headers, data=data, timeout=max(self.cfg.http_timeout_s, 5.0))
        if st != 200:
            raise RuntimeError(f"token refresh failed: {st}")
        payload = json.loads(body.decode("utf-8"))
        return TokenResponse(
            access_token=payload.get("access_token", ""),
            id_token=payload.get("id_token"),
            refresh_token=payload.get("refresh_token"),
            token_type=payload.get("token_type", "Bearer"),
            expires_in=int(payload.get("expires_in", 3600)),
            scope=payload.get("scope"),
            raw=payload
        )

    async def end_session(self, id_token_hint: Optional[str] = None, post_logout_redirect_uri: Optional[str] = None) -> bool:
        url = await self._end_session_endpoint_async()
        if not url:
            # Не все провайдеры поддерживают end_session
            return False
        params: Dict[str, str] = {}
        if id_token_hint:
            params["id_token_hint"] = id_token_hint
        if post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = post_logout_redirect_uri
        st, _h, _b = await self.http.get(url + self._qs(params), timeout=self.cfg.http_timeout_s)
        return st in (200, 204, 302)

    async def handle_backchannel_logout(self, logout_token_jwt: str) -> bool:
        """
        OIDC Back-Channel Logout: logout_token — это JWT от OP.
        Мы не выполняем полную криптографическую проверку (это делает слой валидации),
        но извлекаем sid/jti/sub и инициируем отзыв сессий, если RevocationService доступен.
        """
        try:
            parts = logout_token_jwt.split(".")
            if len(parts) != 3:
                raise ValueError("bad logout token")
            payload = json.loads(_b64u_decode(parts[1]).decode("utf-8"))
        except Exception as e:
            logger.info("logout token parse error: %s", e)
            return False

        sid = str(payload.get("sid") or "")
        jti = str(payload.get("jti") or "")
        exp = int(payload.get("exp") or (_now() + 3600))
        if not (sid or jti):
            return False

        if self.revocation and _HAS_REVOCATION:
            try:
                if jti:
                    await self.revocation.revoke_token(jti=jti, exp=exp, reason=Reason.ADMIN_REVOKE, meta={"src": "backchannel"})
                if sid:
                    await self.revocation.revoke_session(sid=sid, exp=exp, reason=Reason.ADMIN_REVOKE, meta={"src": "backchannel"})
                return True
            except Exception as e:
                logger.warning("revocation failed: %s", e)
                return False
        return True  # нет сервиса отзыва — считаем обработанным

    # ---------------------------
    # Приватные методы
    # ---------------------------

    async def _introspect(self, token: str) -> IntrospectionResult:
        url = await self._introspection_endpoint_async()
        data = {"token": token, "client_id": self.cfg.client_id or ""}
        headers = self._auth_header_basic()
        st, _h, body = await self.http.post(url, headers=headers, data=data, timeout=self.cfg.http_timeout_s)
        if st != 200:
            raise RuntimeError(f"introspection failed: {st}")
        payload = json.loads(body.decode("utf-8"))
        active = bool(payload.get("active"))
        res = IntrospectionResult(
            active=active,
            sub=str(payload.get("sub")) if payload.get("sub") else None,
            scope=payload.get("scope"),
            exp=int(payload.get("exp")) if payload.get("exp") else None,
            iat=int(payload.get("iat")) if payload.get("iat") else None,
            iss=payload.get("iss"),
            aud=payload.get("aud"),
            client_id=payload.get("client_id"),
            username=payload.get("username"),
            token_type=payload.get("token_type"),
            jti=payload.get("jti"),
            sid=payload.get("sid"),
            raw=payload
        )
        return res

    def _validate_iss_aud(self, claims: Mapping[str, Any]) -> None:
        exp_iss = self.cfg.mapping.expected_issuer or self.cfg.issuer
        exp_aud = self.cfg.mapping.expected_audience or self.cfg.audience
        iss = claims.get("iss")
        if exp_iss and iss and str(iss) != str(exp_iss):
            raise RuntimeError("issuer mismatch")
        if exp_aud:
            aud = claims.get("aud")
            if isinstance(aud, list):
                if exp_aud not in aud:
                    raise RuntimeError("audience mismatch")
            elif isinstance(aud, str):
                if aud != exp_aud:
                    raise RuntimeError("audience mismatch")

    def _validate_sub_required(self, claims: Mapping[str, Any]) -> None:
        if self.cfg.require_sub and not str(claims.get("sub") or ""):
            raise RuntimeError("sub required")

    def _qs(self, params: Mapping[str, str]) -> str:
        if not params:
            return ""
        from urllib.parse import urlencode
        return "?" + urlencode(params, doseq=True)

    # ---------------------------
    # Identity mapping helper
    # ---------------------------

    def map_identity(self, claims: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Возвращает нормализованный объект идентичности и роли на его основе.
        """
        self._validate_iss_aud(claims)
        self._validate_sub_required(claims)
        roles = self.cfg.mapping.map_roles(claims)
        amr = claims.get("amr") if isinstance(claims.get("amr"), list) else []
        return {
            "verified": True,
            "iss": claims.get("iss", self.cfg.issuer),
            "aud": claims.get("aud", self.cfg.audience or ""),
            "sub": claims.get("sub", ""),
            "roles": roles,
            "amr": amr,
            "mfa_age_seconds": int(_now() - int(claims.get("auth_time", claims.get("iat", _now())))),
            "claims": claims,
        }

    async def close(self) -> None:
        try:
            await self.http.close()
        except Exception:
            pass


# =============================================================================
# Реестр IdP
# =============================================================================

class IdPRegistry:
    """
    Реестр нескольких IdP по ключу (например, tenant/realm).
    """
    def __init__(self):
        self._adapters: Dict[str, OIDCAdapter] = {}
        self._lock = asyncio.Lock()
        self._revocation: Optional["RevocationService"] = None

    async def init_revocation(self) -> None:
        if _HAS_REVOCATION and self._revocation is None:
            try:
                backend = await build_backend_from_env()  # type: ignore
                self._revocation = RevocationService(backend)  # type: ignore
            except Exception as e:
                logger.warning("revocation init failed: %s", e)
                self._revocation = None

    async def get(self, key: str) -> Optional[OIDCAdapter]:
        async with self._lock:
            return self._adapters.get(key)

    async def register(self, key: str, cfg: IdPConfig) -> OIDCAdapter:
        async with self._lock:
            if key in self._adapters:
                return self._adapters[key]
            await self.init_revocation()
            adapter = OIDCAdapter(cfg, http=build_http_client(), revocation=self._revocation)
            self._adapters[key] = adapter
            return adapter

    async def close(self) -> None:
        async with self._lock:
            for a in self._adapters.values():
                try:
                    await a.close()
                except Exception:
                    pass
            self._adapters.clear()


# =============================================================================
# Пример использования (докстринг)
# =============================================================================
"""
Пример:

cfg = IdPConfig(
    issuer="https://auth.example.com/realms/acme",
    client_id="core-api",
    client_secret=os.getenv("IDP_CLIENT_SECRET"),
    use_introspection=True,
    audience="api://core",
    mapping=IdentityMapping(
        roles_claim="realm_access.roles",
        role_map={"realm_access.roles": {"admin": ["role:admin"], "user": ["role:read"]}},
        expected_issuer="https://auth.example.com/realms/acme",
        expected_audience="api://core",
    ),
    name="acme"
)

adapter = OIDCAdapter(cfg)

# Проверка токена:
claims = await adapter.verify_access_token(access_token)
identity = adapter.map_identity(claims)

# UserInfo:
uinfo = await adapter.get_userinfo(access_token)

# Обмен кода:
tokens = await adapter.exchange_code(code, redirect_uri, code_verifier)

# Refresh:
tokens = await adapter.refresh(refresh_token)

# Backchannel logout:
await adapter.handle_backchannel_logout(logout_token_jwt)

await adapter.close()
"""
