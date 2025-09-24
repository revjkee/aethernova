# -*- coding: utf-8 -*-
"""
mythos-core/api/http/middleware/cors.py

Промышленный CORS middleware для ASGI-приложений.
Совместим с FastAPI/Starlette/Sanic/любой ASGI-перегородкой.

Особенности:
- allow_origins: точные значения, шаблоны типа '*.example.com' и/или регулярные выражения
- allow_credentials: безопасная логика (никогда не шлёт '*' при credentials=true)
- allow_methods / allow_headers / expose_headers: строгие списки, '*' и эхо запрошенных
- allow_null_origin: поддержка Origin: null (встраиваемые сценарии/файловые URL)
- Access-Control-Allow-Private-Network: опционально (Chrome PNA, экспериментально)
- Корректные заголовки Vary для кэширования
- Max-Age для preflight
- Конфигурация из окружения (MYTHOS_CORS_*) и/или программно

Использование (FastAPI):
    from fastapi import FastAPI
    from mythos_core.api.http.middleware.cors import CORSPolicy, CORSMiddleware

    app = FastAPI()
    policy = CORSPolicy(
        allow_origins=["https://app.example.com", "*.example.org"],
        allow_origin_regex=[r"^https://([a-z0-9-]+)\\.tenant\\.example\\.com$"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
        max_age=600,
        allow_private_network=False,
        allow_null_origin=False,
    )
    app.add_middleware(CORSMiddleware, policy=policy)

Лицензия: proprietary (Aethernova / Mythos Core)
"""

from __future__ import annotations

import os
import re
import typing as T
from dataclasses import dataclass, field

from types import SimpleNamespace
from urllib.parse import urlparse

Scope = T.Dict[str, T.Any]
Receive = T.Callable[[], T.Awaitable[T.Dict[str, T.Any]]]
Send = T.Callable[[T.Dict[str, T.Any]], T.Awaitable[None]]

# ---------------------------
# Вспомогательные утилиты
# ---------------------------

def _csv_env(name: str, default: T.Iterable[str] | None = None) -> list[str]:
    raw = os.getenv(name)
    if not raw:
        return list(default or [])
    return [x.strip() for x in raw.split(",") if x.strip()]

def _wildcard_to_regex(pattern: str) -> re.Pattern[str]:
    """
    Преобразует шаблон вида '*.example.com' в безопасный regex.
    """
    # Защитное экранирование всего, затем подмена ведущего '*.' на групповой wildcard
    if pattern.startswith("*."):
        tail = re.escape(pattern[2:])
        return re.compile(rf"^https?://([a-z0-9-]+\.)+{tail}$", re.IGNORECASE)
    # '*' в середине не поддерживаем как шаблон (слишком опасно) — воспринимаем буквально
    return re.compile(re.escape(pattern), re.IGNORECASE)

def _normalize_origin(origin: str) -> str:
    # Нормализуем схему/хост/порт для точных сравнений
    if origin == "null":
        return "null"
    try:
        p = urlparse(origin)
        scheme = (p.scheme or "").lower()
        host = (p.hostname or "").lower()
        port = p.port
        # Явно укажем порт только если он не стандартный
        if (scheme == "http" and port in (None, 80)) or (scheme == "https" and port in (None, 443)):
            return f"{scheme}://{host}"
        if scheme and host and port:
            return f"{scheme}://{host}:{port}"
    except Exception:
        pass
    return origin

def _lower_set(items: T.Iterable[str]) -> set[str]:
    return {i.lower() for i in items}

# ---------------------------
# Конфигурация CORS
# ---------------------------

@dataclass(frozen=True)
class CORSPolicy:
    allow_origins: list[str] = field(default_factory=list)
    allow_origin_regex: list[str] = field(default_factory=list)
    allow_methods: list[str] = field(default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    allow_headers: list[str] = field(default_factory=lambda: ["*"])
    expose_headers: list[str] = field(default_factory=list)
    allow_credentials: bool = False
    max_age: int = 600  # seconds
    allow_private_network: bool = False
    allow_null_origin: bool = False

    @classmethod
    def from_env(cls) -> "CORSPolicy":
        """
        Инициализация политики из переменных окружения:
        - MYTHOS_CORS_ALLOW_ORIGINS: CSV, поддерживает '*.example.com'
        - MYTHOS_CORS_ALLOW_ORIGIN_REGEX: CSV regex
        - MYTHOS_CORS_ALLOW_METHODS: CSV
        - MYTHOS_CORS_ALLOW_HEADERS: CSV (используйте '*' для любых)
        - MYTHOS_CORS_EXPOSE_HEADERS: CSV
        - MYTHOS_CORS_ALLOW_CREDENTIALS: '1'|'true'
        - MYTHOS_CORS_MAX_AGE: seconds
        - MYTHOS_CORS_ALLOW_PRIVATE_NETWORK: '1'|'true'
        - MYTHOS_CORS_ALLOW_NULL_ORIGIN: '1'|'true'
        """
        def _truth(name: str) -> bool:
            return os.getenv(name, "").lower() in ("1", "true", "yes", "on")

        max_age = int(os.getenv("MYTHOS_CORS_MAX_AGE", "600"))
        return cls(
            allow_origins=_csv_env("MYTHOS_CORS_ALLOW_ORIGINS"),
            allow_origin_regex=_csv_env("MYTHOS_CORS_ALLOW_ORIGIN_REGEX"),
            allow_methods=_csv_env("MYTHOS_CORS_ALLOW_METHODS", ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]),
            allow_headers=_csv_env("MYTHOS_CORS_ALLOW_HEADERS", ["*"]),
            expose_headers=_csv_env("MYTHOS_CORS_EXPOSE_HEADERS", []),
            allow_credentials=_truth("MYTHOS_CORS_ALLOW_CREDENTIALS"),
            max_age=max_age,
            allow_private_network=_truth("MYTHOS_CORS_ALLOW_PRIVATE_NETWORK"),
            allow_null_origin=_truth("MYTHOS_CORS_ALLOW_NULL_ORIGIN"),
        )

# ---------------------------
# ASGI Middleware
# ---------------------------

class CORSMiddleware:
    """
    Промышленный CORS middleware.

    Внимание к безопасности:
    - Если allow_credentials=True, «*» в Access-Control-Allow-Origin не используется — эхо конкретного origin
    - В preflight всегда проставляется корректный набор Vary
    - Заголовки сравниваются case-insensitive
    """

    def __init__(self, app: T.Callable, policy: CORSPolicy):
        self.app = app
        self.policy = policy

        # Точные origin-ы
        self._exact: set[str] = { _normalize_origin(o) for o in policy.allow_origins if o != "*" and not o.startswith("*.") }
        self._allow_all: bool = "*" in policy.allow_origins

        # Шаблоны вида '*.example.com'
        self._wildcards: list[re.Pattern[str]] = [
            _wildcard_to_regex(o) for o in policy.allow_origins if o.startswith("*.") and len(o) > 2
        ]

        # Явные regex
        self._regex: list[re.Pattern[str]] = [ re.compile(rx, re.IGNORECASE) for rx in policy.allow_origin_regex ]

        # Нормализованные методы и заголовки
        self._methods: set[str] = _lower_set(policy.allow_methods) if "*" not in policy.allow_methods else {"*"}
        self._headers: set[str] = _lower_set(policy.allow_headers) if "*" not in policy.allow_headers else {"*"}

        # Expose headers (как есть, но в ответе будем унифицировать регистр для читаемости)
        self._expose: list[str] = policy.expose_headers

    # ---------- Внутренние проверки ----------

    def _is_origin_allowed(self, origin: str | None) -> tuple[bool, str | None]:
        if not origin:
            return False, None
        origin_norm = _normalize_origin(origin)

        if origin_norm == "null":
            if self.policy.allow_null_origin:
                return True, "null"
            return False, None

        if self._allow_all and not self.policy.allow_credentials:
            # Можно безопасно вернуть '*'
            return True, "*"

        if origin_norm in self._exact:
            return True, origin  # ответим исходным значением Origin

        for rx in self._wildcards:
            if rx.match(origin):
                return True, origin

        for rx in self._regex:
            if rx.match(origin):
                return True, origin

        if self._allow_all and self.policy.allow_credentials:
            # Разрешено всё, но из-за credentials ответим эхо-origin
            return True, origin

        return False, None

    def _is_method_allowed(self, method: str) -> bool:
        return "*" in self._methods or method.lower() in self._methods

    def _are_headers_allowed(self, requested: str | None) -> tuple[bool, str]:
        """
        Возвращает (разрешено, allow_header_value).
        Если политика '*', эхоим запрошенные заголовки.
        """
        if requested is None or requested.strip() == "":
            return True, ""
        if "*" in self._headers:
            # Эхоим, как пришло (браузер сопоставит регистр сам)
            return True, requested
        req = [h.strip().lower() for h in requested.split(",") if h.strip()]
        not_allowed = [h for h in req if h not in self._headers]
        return (len(not_allowed) == 0, ", ".join([h for h in requested.split(",") if h.strip()]))

    # ---------- ASGI интерфейс ----------

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = _headers_as_dict(scope.get("headers") or [])
        origin = headers.get("origin")

        # Preflight
        if (scope["method"] or "").upper() == "OPTIONS" and "access-control-request-method" in headers:
            await self._handle_preflight(scope, receive, send, headers, origin)
            return

        # Обычный запрос
        allowed, allowed_origin_value = self._is_origin_allowed(origin)
        if not allowed:
            # Просто пробрасываем дальше без CORS-хедеров
            await self.app(scope, receive, send)
            return

        # Оборачиваем send для модификации ответных заголовков
        async def send_wrapper(message: dict) -> None:
            if message["type"] == "http.response.start":
                raw = message.setdefault("headers", [])
                hv = HeadersView(raw)
                hv.add("Vary", "Origin")

                # Access-Control-Allow-Origin
                if allowed_origin_value == "*":
                    # Разрешено без credentials
                    hv.set("Access-Control-Allow-Origin", "*")
                else:
                    hv.set("Access-Control-Allow-Origin", allowed_origin_value or origin or "*")

                # Credentials (если включены)
                if self.policy.allow_credentials:
                    hv.set("Access-Control-Allow-Credentials", "true")

                # Expose headers
                if self._expose:
                    hv.set("Access-Control-Expose-Headers", ", ".join(self._expose))
            await send(message)

        await self.app(scope, receive, send_wrapper)

    async def _handle_preflight(
        self, scope: Scope, receive: Receive, send: Send, headers: dict[str, str], origin: str | None
    ) -> None:
        request_method = headers.get("access-control-request-method", "")
        request_headers = headers.get("access-control-request-headers", "")

        allowed, allowed_origin_value = self._is_origin_allowed(origin)
        method_ok = self._is_method_allowed(request_method)
        headers_ok, allow_headers_value = self._are_headers_allowed(request_headers)

        # Ответ 204 с корректным набором заголовков (или 400 при явном отказе)
        status = 204 if (allowed and method_ok and headers_ok) else 400
        response_headers: list[tuple[bytes, bytes]] = []

        hv = HeadersView(response_headers)
        hv.add("Vary", "Origin")
        hv.add("Vary", "Access-Control-Request-Method")
        hv.add("Vary", "Access-Control-Request-Headers")

        if allowed:
            if allowed_origin_value == "*":
                hv.set("Access-Control-Allow-Origin", "*")
            else:
                hv.set("Access-Control-Allow-Origin", allowed_origin_value or (origin or ""))

            if self.policy.allow_credentials:
                hv.set("Access-Control-Allow-Credentials", "true")

        if method_ok:
            # По спецификации можно вернуть список разрешённых, но чаще — эхо запрошенного
            hv.set("Access-Control-Allow-Methods", request_method.upper())
        else:
            hv.set("Access-Control-Allow-Methods", ", ".join(sorted({m.upper() for m in self._methods if m != "*"})))

        if headers_ok:
            if allow_headers_value:
                hv.set("Access-Control-Allow-Headers", allow_headers_value)
        else:
            # Вернём явный список допустимых
            if "*" not in self._headers and self._headers:
                hv.set("Access-Control-Allow-Headers", ", ".join(sorted({h for h in self._headers})))

        if self.policy.max_age > 0:
            hv.set("Access-Control-Max-Age", str(self.policy.max_age))

        # Private Network Access (экспериментально)
        if self.policy.allow_private_network and headers.get("access-control-request-private-network", "").lower() == "true":
            hv.set("Access-Control-Allow-Private-Network", "true")

        await _send_empty_response(send, status, response_headers)

# ---------------------------
# Низкоуровневые helpers ASGI/заголовков
# ---------------------------

def _headers_as_dict(raw_headers: T.Iterable[T.Tuple[bytes, bytes]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in raw_headers:
        ks = k.decode("latin-1").lower()
        vs = v.decode("latin-1")
        out[ks] = vs
    return out

class HeadersView:
    """
    Удобная обёртка над списком пар (name: bytes, value: bytes) из ASGI-сообщения.
    Позволяет set/add, соблюдая регистр заголовков в ответе.
    """
    __slots__ = ("_raw",)

    def __init__(self, raw: list[tuple[bytes, bytes]]):
        self._raw = raw

    def add(self, name: str, value: str) -> None:
        self._raw.append((name.encode("latin-1"), value.encode("latin-1")))

    def set(self, name: str, value: str) -> None:
        name_l = name.lower().encode("latin-1")
        i = 0
        while i < len(self._raw):
            if self._raw[i][0].lower() == name_l:
                del self._raw[i]
            else:
                i += 1
        self._raw.append((name.encode("latin-1"), value.encode("latin-1")))

async def _send_empty_response(send: Send, status: int, headers: list[tuple[bytes, bytes]]) -> None:
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": b"", "more_body": False})
