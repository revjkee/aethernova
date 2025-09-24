"""
automation_core.http_client.auth
--------------------------------

Промышленный модуль аутентификации для асинхронного HTTP-клиента.

Возможности:
- Единый интерфейс BaseAuth для стратегий аутентификации.
- OAuth2 Client Credentials: безопасное кэширование и автообновление токена.
- OAuth2 Authorization Code + PKCE: обмен кода на токен, обновление по refresh_token.
- API Key: заголовок/квери/кука.
- HMAC-подпись: детерминированная каноникализация и подпись запроса.
- Композитная аутентификация (несколько стратегий одновременно).
- Защита от гонок при обновлении токена (asyncio.Lock).
- Leeway (допуск) по времени истечения токена, защита от clock skew.
- Интеграция с httpx.AsyncClient через event hooks.
- Никакой чувствительной информации в логах.

Зависимости:
  - httpx>=0.27.0

Замечание:
  - Реализации не зависят от фреймворка и легко тестируются.
  - Для PKCE предусмотрены утилиты code_verifier/code_challenge (S256).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, MutableMapping, Optional, Protocol, Sequence, Tuple, Union, List

import httpx


# ============================ ВСПОМОГАТЕЛЬНЫЕ УТИЛИТЫ ============================

def _now_ts() -> int:
    return int(time.time())

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _mask(s: Optional[str], keep: int = 4) -> str:
    """Маскирует секреты для логов/отладочной печати."""
    if not s:
        return ""
    return (s[:keep] + "…" + s[-keep:]) if len(s) > 2 * keep else "***"

def _canonical_query(params: Mapping[str, Any]) -> str:
    """Каноникализация квери-параметров для HMAC (по ключу, стабильная сериализация)."""
    # Превращаем значения в строки, сортируем по ключу, соединяем &'ами без экранирования.
    parts: List[str] = []
    for k in sorted(params.keys()):
        v = params[k]
        if isinstance(v, (list, tuple)):
            for item in v:
                parts.append(f"{k}={item}")
        else:
            parts.append(f"{k}={v}")
    return "&".join(parts)

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ================================ БАЗОВЫЕ ТИПЫ ==================================

class BaseAuth(Protocol):
    """
    Интерфейс стратегии аутентификации.
    Должна возвращать набор заголовков, которые будут добавлены к запросу.
    """
    async def auth_headers(self, request: httpx.Request) -> Mapping[str, str]:
        ...

    def __repr.sanitized__(self) -> str:
        """Безопасное представление для логов."""
        return self.__class__.__name__


@dataclass
class OAuth2Token:
    access_token: str
    token_type: str = "Bearer"
    expires_at: Optional[int] = None     # Unix timestamp (sec)
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_response(cls, data: Mapping[str, Any], leeway_sec: int = 15) -> "OAuth2Token":
        access_token = str(data.get("access_token", ""))
        token_type = str(data.get("token_type", "Bearer"))
        refresh_token = data.get("refresh_token")
        scope = data.get("scope")
        expires_in = data.get("expires_in")
        expires_at = None
        if isinstance(expires_in, (int, float)):
            # небольшой запас (leeway) для нивелирования clock skew
            expires_at = _now_ts() + int(expires_in) - max(0, leeway_sec)
        return cls(
            access_token=access_token,
            token_type=token_type or "Bearer",
            refresh_token=str(refresh_token) if refresh_token else None,
            scope=str(scope) if scope else None,
            raw=dict(data),
        )

    def is_expired(self) -> bool:
        return self.expires_at is not None and _now_ts() >= self.expires_at

    def header_value(self) -> str:
        return f"{self.token_type} {self.access_token}"


# ============================ OAUTH2: CLIENT CREDENTIALS =========================

class OAuth2ClientCredentialsAuth:
    """
    OAuth2 Client Credentials flow.
    - Получение токена у authorization server (token_endpoint).
    - Кэширование и автообновление с блокировкой от гонок.
    """
    def __init__(
        self,
        token_endpoint: str,
        client_id: str,
        client_secret: str,
        scope: Optional[Union[str, Sequence[str]]] = None,
        audience: Optional[str] = None,
        timeout: float = 10.0,
        token_leeway_sec: int = 15,
        http_client: Optional[httpx.AsyncClient] = None,
        extra: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self._token_endpoint = token_endpoint
        self._client_id = client_id
        self._client_secret = client_secret
        self._scope = scope if isinstance(scope, str) or scope is None else " ".join(scope)
        self._audience = audience
        self._timeout = timeout
        self._leeway = token_leeway_sec
        self._http = http_client
        self._extra = dict(extra or {})
        self._token: Optional[OAuth2Token] = None
        self._lock = asyncio.Lock()

    async def _ensure_http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=self._timeout)
        return self._http

    async def _obtain_token(self) -> OAuth2Token:
        client = await self._ensure_http()
        data: Dict[str, Any] = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }
        if self._scope:
            data["scope"] = self._scope
        if self._audience:
            # Не все провайдеры поддерживают audience; оставляем опционально
            data["audience"] = self._audience
        data.update(self._extra)

        resp = await client.post(self._token_endpoint, data=data)
        resp.raise_for_status()
        payload = resp.json()
        token = OAuth2Token.from_response(payload, leeway_sec=self._leeway)
        self._token = token
        return token

    async def _get_token(self) -> OAuth2Token:
        # Быстрый путь: валидный токен в кеше
        if self._token and not self._token.is_expired():
            return self._token
        # Медленный путь: синхронизация между сопр routine-ами
        async with self._lock:
            if self._token and not self._token.is_expired():
                return self._token
            return await self._obtain_token()

    async def auth_headers(self, request: httpx.Request) -> Mapping[str, str]:
        tok = await self._get_token()
        return {"Authorization": tok.header_value()}

    def __repr.sanitized__(self) -> str:  # noqa: N802
        return f"OAuth2ClientCredentialsAuth(client_id={_mask(self._client_id)})"


# =============================== OAUTH2: PKCE FLOW ===============================

def generate_code_verifier(length: int = 64) -> str:
    """
    Генерирует PKCE code_verifier. RFC 7636: [43, 128] символов.
    """
    length = max(43, min(length, 128))
    return _b64url(hashlib.sha256(str(time.time_ns()).encode()).digest())[:length]

def code_challenge_s256(verifier: str) -> str:
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


class OAuth2PKCEAuth:
    """
    OAuth2 Authorization Code + PKCE.
    Применимо в бекенд-сценариях после получения authorization_code.
    - Обменивает code на access_token/refresh_token.
    - Обновляет по refresh_token при истечении.
    """
    def __init__(
        self,
        token_endpoint: str,
        client_id: str,
        redirect_uri: str,
        code_verifier: str,
        authorization_code: Optional[str] = None,
        refresh_token: Optional[str] = None,
        timeout: float = 10.0,
        token_leeway_sec: int = 15,
        http_client: Optional[httpx.AsyncClient] = None,
        extra: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self._token_endpoint = token_endpoint
        self._client_id = client_id
        self._redirect_uri = redirect_uri
        self._code_verifier = code_verifier
        self._http = http_client
        self._timeout = timeout
        self._leeway = token_leeway_sec
        self._extra = dict(extra or {})
        self._token: Optional[OAuth2Token] = None
        self._lock = asyncio.Lock()

        # Первичное состояние может быть задано заранее
        if refresh_token:
            self._token = OAuth2Token(access_token="", token_type="Bearer", refresh_token=refresh_token)
        self._authorization_code = authorization_code

    async def _ensure_http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=self._timeout)
        return self._http

    async def exchange_code(self, authorization_code: str) -> OAuth2Token:
        client = await self._ensure_http()
        data = {
            "grant_type": "authorization_code",
            "client_id": self._client_id,
            "code": authorization_code,
            "redirect_uri": self._redirect_uri,
            "code_verifier": self._code_verifier,
            **self._extra,
        }
        resp = await client.post(self._token_endpoint, data=data)
        resp.raise_for_status()
        tok = OAuth2Token.from_response(resp.json(), leeway_sec=self._leeway)
        self._token = tok
        # После обмена authorization_code больше не нужен
        self._authorization_code = None
        return tok

    async def _refresh(self, refresh_token: str) -> OAuth2Token:
        client = await self._ensure_http()
        data = {
            "grant_type": "refresh_token",
            "client_id": self._client_id,
            "refresh_token": refresh_token,
            **self._extra,
        }
        resp = await client.post(self._token_endpoint, data=data)
        resp.raise_for_status()
        tok = OAuth2Token.from_response(resp.json(), leeway_sec=self._leeway)
        # Некоторые провайдеры отдают новый refresh_token; поддержим оба случая
        if not tok.refresh_token:
            tok.refresh_token = refresh_token
        self._token = tok
        return tok

    async def _ensure_token(self) -> OAuth2Token:
        # Имеем валидный токен
        if self._token and self._token.access_token and not self._token.is_expired():
            return self._token

        async with self._lock:
            # Повторная проверка после захвата блокировки
            if self._token and self._token.access_token and not self._token.is_expired():
                return self._token

            # 1) Если есть authorization_code (первичный обмен)
            if self._authorization_code:
                return await self.exchange_code(self._authorization_code)

            # 2) Иначе пытаемся обновить по refresh_token
            if self._token and self._token.refresh_token:
                return await self._refresh(self._token.refresh_token)

            raise RuntimeError("OAuth2PKCEAuth: нет действующего access_token и отсутствуют средства получения (code/refresh_token)")

    async def auth_headers(self, request: httpx.Request) -> Mapping[str, str]:
        tok = await self._ensure_token()
        return {"Authorization": tok.header_value()}

    def __repr.sanitized__(self) -> str:  # noqa: N802
        return f"OAuth2PKCEAuth(client_id={_mask(self._client_id)})"


# ================================ API KEY AUTH ==================================

class ApiKeyLocation:
    HEADER = "header"
    QUERY = "query"
    COOKIE = "cookie"


class ApiKeyAuth:
    """
    Простая API-key аутентификация.
    - location="header" -> добавляет заголовок {header_name}: {prefix}{key}
    - location="query"  -> добавляет ?{param}={key}
    - location="cookie" -> добавляет Cookie: {cookie_name}={key}
    """
    def __init__(
        self,
        key: str,
        location: str = ApiKeyLocation.HEADER,
        name: str = "X-API-Key",
        prefix: Optional[str] = None,
    ) -> None:
        self._key = key
        self._location = location
        self._name = name
        self._prefix = prefix or ""

    async def auth_headers(self, request: httpx.Request) -> Mapping[str, str]:
        if self._location == ApiKeyLocation.HEADER:
            return {self._name: f"{self._prefix}{self._key}".strip()}
        elif self._location == ApiKeyLocation.COOKIE:
            # Добавляем/сливаем с существующими куками
            cookie_value = f"{self._name}={self._key}"
            existing = request.headers.get("Cookie")
            return {"Cookie": f"{existing}; {cookie_value}" if existing else cookie_value}
        else:
            # QUERY — модифицируем URL уже в hook (см. attach_auth ниже),
            # здесь возвращаем пустые заголовки.
            return {}

    def update_url_params(self, url: httpx.URL) -> httpx.URL:
        if self._location != ApiKeyLocation.QUERY:
            return url
        params = dict(url.params)
        params[self._name] = f"{self._prefix}{self._key}".strip()
        return url.copy_with(params=params)

    def __repr.sanitized__(self) -> str:  # noqa: N802
        return f"ApiKeyAuth(name={self._name}, location={self._location}, key={_mask(self._key)})"


# ================================= HMAC AUTH ====================================

class HmacAuth:
    """
    HMAC-подпись запроса:
    - Каноникализация: METHOD \n PATH \n CANON_QUERY \n SHA256_BODY_HEX \n TIMESTAMP
    - Заголовки по умолчанию: X-Access-Key, X-Signature, X-Timestamp
    - Алгоритм: HMAC-SHA256
    """
    def __init__(
        self,
        access_key: str,
        secret_key: str,
        header_access: str = "X-Access-Key",
        header_signature: str = "X-Signature",
        header_timestamp: str = "X-Timestamp",
        clock_skew_leeway_sec: int = 10,
    ) -> None:
        self._ak = access_key
        self._sk = secret_key.encode("utf-8")
        self._h_access = header_access
        self._h_signature = header_signature
        self._h_timestamp = header_timestamp
        self._leeway = max(0, clock_skew_leeway_sec)

    def _signature(self, method: str, path: str, query: str, body_digest_hex: str, ts: int) -> str:
        payload = "\n".join([method.upper(), path, query, body_digest_hex, str(ts)]).encode("utf-8")
        return hmac.new(self._sk, payload, hashlib.sha256).hexdigest()

    async def auth_headers(self, request: httpx.Request) -> Mapping[str, str]:
        # ВАЖНО: тело может быть None или stream — для простоты берём .content (httpx собирает при готовом теле)
        content = request.content or b""
        body_hex = _sha256_hex(content if isinstance(content, (bytes, bytearray)) else bytes(content))
        ts = _now_ts()
        sig = self._signature(
            method=request.method,
            path=request.url.raw_path.decode("utf-8"),
            query=_canonical_query(dict(request.url.params)),
            body_digest_hex=body_hex,
            ts=ts,
        )
        return {
            self._h_access: self._ak,
            self._h_timestamp: str(ts),
            self._h_signature: sig,
        }

    def __repr.sanitized__(self) -> str:  # noqa: N802
        return f"HmacAuth(access_key={_mask(self._ak)})"


# ============================== КОМПОЗИТНАЯ СТРАТЕГИЯ ===========================

class CompositeAuth:
    """
    Композиция нескольких стратегий. Порядок важен: более специфичные раньше.
    - Заголовки мерджатся, при конфликте — правый приоритет (последняя стратегия).
    - URL-параметры для ApiKeyAuth(query) встраиваются в хуке (см. attach_auth).
    """
    def __init__(self, *strategies: BaseAuth) -> None:
        self._strategies: Tuple[BaseAuth, ...] = strategies

    async def auth_headers(self, request: httpx.Request) -> Mapping[str, str]:
        merged: Dict[str, str] = {}
        for strat in self._strategies:
            h = await strat.auth_headers(request)
            if h:
                merged.update(h)
        return merged

    @property
    def strategies(self) -> Tuple[BaseAuth, ...]:
        return self._strategies

    def __repr.sanitized__(self) -> str:  # noqa: N802
        return "CompositeAuth(" + ", ".join(s.__repr.sanitized__() for s in self._strategies) + ")"


# ============================ ИНТЕГРАЦИЯ С HTTPX КЛИЕНТОМ =======================

async def _auth_request_hook(request: httpx.Request, auth: Union[BaseAuth, CompositeAuth]) -> None:
    """
    Хук, добавляющий заголовки и (при необходимости) модифицирующий URL.
    Вызывается httpx перед отправкой запроса.
    """
    # Обновим query-параметры для ApiKeyAuth(location=query)
    if isinstance(auth, CompositeAuth):
        strategies = auth.strategies
    else:
        strategies = (auth,)

    new_url = request.url
    for strat in strategies:
        if isinstance(strat, ApiKeyAuth) and strat._location == ApiKeyLocation.QUERY:  # noqa: SLF001
            new_url = strat.update_url_params(new_url)

    if new_url != request.url:
        request.url = new_url

    # Заголовки авторизации
    headers = await auth.auth_headers(request)
    for k, v in headers.items():
        # Не перетираем уже установленные приложениям заголовки, если они есть
        if k not in request.headers:
            request.headers[k] = v

def build_auth_client(
    auth: Union[BaseAuth, CompositeAuth],
    base_url: Optional[str] = None,
    timeout: float = 30.0,
    transport: Optional[httpx.AsyncBaseTransport] = None,
    **client_kwargs: Any,
) -> httpx.AsyncClient:
    """
    Создаёт httpx.AsyncClient с установленными хуками аутентификации.
    Пример:
        auth = OAuth2ClientCredentialsAuth(token_endpoint=..., client_id=..., client_secret=...)
        client = build_auth_client(auth, base_url="https://api.example.com")
        resp = await client.get("/v1/resource")
    """
    event_hooks = client_kwargs.pop("event_hooks", {})
    request_hooks = list(event_hooks.get("request", []))
    # Встроим наш хук в цепочку
    request_hooks.append(lambda req: _auth_request_hook(req, auth))
    event_hooks["request"] = request_hooks

    return httpx.AsyncClient(
        base_url=base_url,
        timeout=timeout,
        transport=transport,
        event_hooks=event_hooks,
        **client_kwargs,
    )


# ============================== ПРИМЕР ИСПОЛЬЗОВАНИЯ ============================
# (оставлено в виде документационного комментария, не выполняется)
#
# async def example():
#     oauth = OAuth2ClientCredentialsAuth(
#         token_endpoint="https://auth.example.com/oauth/token",
#         client_id="client_id",
#         client_secret="client_secret",
#         scope=["read", "write"],
#     )
#     api_key = ApiKeyAuth(key="my-api-key", location=ApiKeyLocation.HEADER, name="X-API-Key")
#     signer = HmacAuth(access_key="ak", secret_key="sk")
#     auth = CompositeAuth(oauth, api_key, signer)
#
#     async with build_auth_client(auth, base_url="https://api.example.com") as client:
#         r = await client.get("/v1/ping")
#         r.raise_for_status()
#         return r.json()
#
# =================================================================================
