#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Engine-Core HTTP API — CORS middleware (hardened)

Возможности:
- Динамическая валидация Origin: allowlist, denylist, wildcard поддомены (*.example.com), regex
- Безопасная политика: echo-allowed-origin вместо '*' при credentials=true
- Корректная обработка preflight (OPTIONS) и обычных CORS-запросов
- Гибкая настройка методов/заголовков/Expose-Headers и max-age
- Принудительный Vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers
- Защита: отклонение небезопасных схем (http для продакшна), опциональная блокировка приватных сетей
- Конфигурация через ENV (ENGINE_CORS_*)
"""

from __future__ import annotations

import os
import re
from typing import Iterable, List, Optional, Pattern, Set, Tuple

from fastapi import Request, Response, status
from starlette.types import ASGIApp, Receive, Scope, Send
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator

# =============================================================================
# Настройки
# =============================================================================

class CORSSettings(BaseSettings):
    # Управление
    CORS_ENABLED: bool = True
    CORS_ALLOW_CREDENTIALS: bool = False
    CORS_MAX_AGE: int = 600  # seconds to cache preflight
    CORS_STRICT_HTTPS: bool = True  # отклонять http-origin в production
    CORS_BLOCK_PRIVATE_NETWORK: bool = False  # отклонять Private-Network preflight (Chrome PNA)

    # Источники
    CORS_ALLOW_ORIGINS: List[str] = Field(default_factory=list)          # точные origin'ы (https://app.example.com)
    CORS_ALLOW_ORIGIN_WILDCARDS: List[str] = Field(default_factory=list) # маски (*.example.com)
    CORS_ALLOW_ORIGIN_REGEXES: List[str] = Field(default_factory=list)   # regex строки (скомпилируются)
    CORS_DENY_ORIGINS: List[str] = Field(default_factory=list)           # явный denylist (перевес над allow)

    # Методы/заголовки
    CORS_ALLOW_METHODS: List[str] = Field(default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "PATCH"])
    CORS_ALLOW_HEADERS: List[str] = Field(default_factory=lambda: ["authorization", "content-type", "x-request-id"])
    CORS_EXPOSE_HEADERS: List[str] = Field(default_factory=lambda: ["x-request-id"])

    # Дополнительно
    CORS_ALLOW_ALL_SUBDOMAINS_OF: List[str] = Field(default_factory=list)  # эквивалент *.example.com

    model_config = SettingsConfigDict(env_prefix="ENGINE_", case_sensitive=False)

    @field_validator("CORS_ALLOW_METHODS")
    @classmethod
    def _norm_methods(cls, v: List[str]) -> List[str]:
        return sorted({m.upper() for m in v})

    @field_validator("CORS_ALLOW_HEADERS", "CORS_EXPOSE_HEADERS")
    @classmethod
    def _norm_headers(cls, v: List[str]) -> List[str]:
        return sorted({h.lower() for h in v})


settings = CORSSettings()

# Предкомпилированные regex
_WILDCARD_PATTERNS: List[Pattern[str]] = []
_REGEX_PATTERNS: List[Pattern[str]] = []

def _compile_patterns():
    global _WILDCARD_PATTERNS, _REGEX_PATTERNS
    _WILDCARD_PATTERNS = []
    for mask in settings.CORS_ALLOW_ORIGIN_WILDCARDS + [f"*.{d}" for d in settings.CORS_ALLOW_ALL_SUBDOMAINS_OF]:
        # Превращаем *.example.com -> r"^https?://([A-Za-z0-9-]+\.)*example\.com(?::\d+)?$"
        domain = re.escape(mask.replace("*.", ""))
        pat = re.compile(rf"^https?://([A-Za-z0-9-]+\.)*{domain}(?::\d+)?$")
        _WILDCARD_PATTERNS.append(pat)
    _REGEX_PATTERNS = [re.compile(rx) for rx in settings.CORS_ALLOW_ORIGIN_REGEXES]

_compile_patterns()

# =============================================================================
# Утилиты
# =============================================================================

def _origin_scheme_is_secure(origin: str) -> bool:
    return origin.startswith("https://") or origin.startswith("chrome-extension://") or origin.startswith("moz-extension://")

def _origin_matches(origin: str) -> bool:
    if not origin:
        return False

    # Denylist — приоритетнее
    if any(origin == d for d in settings.CORS_DENY_ORIGINS):
        return False

    # Точные совпадения
    if origin in settings.CORS_ALLOW_ORIGINS:
        return True

    # Wildcards (*.example.com)
    for pat in _WILDCARD_PATTERNS:
        if pat.match(origin):
            return True

    # Regex
    for pat in _REGEX_PATTERNS:
        if pat.match(origin):
            return True

    return False

def _should_allow_origin(origin: str) -> bool:
    if not settings.CORS_ENABLED:
        return False
    if settings.CORS_STRICT_HTTPS and origin and origin.startswith("http://"):
        # запрет небезопасных схем в проде
        return False
    return _origin_matches(origin)

def _vary(headers: list, key: str):
    # добавляет/расширяет заголовок Vary
    vary_key = b"vary"
    existing = None
    for i, (k, v) in enumerate(headers):
        if k.lower() == vary_key:
            existing = (i, v)
            break
    if existing is None:
        headers.append((b"Vary", key.encode()))
    else:
        i, v = existing
        current = v.decode()
        if key.lower() not in [x.strip().lower() for x in current.split(",")]:
            headers[i] = (b"Vary", f"{current}, {key}".encode())

# =============================================================================
# Middleware
# =============================================================================

class HardenedCORSMiddleware:
    """
    ASGI middleware с расширенной логикой CORS поверх Starlette.

    Подключение:
        app.add_middleware(HardenedCORSMiddleware)
    """
    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self.allow_credentials = settings.CORS_ALLOW_CREDENTIALS
        self.allow_methods = settings.CORS_ALLOW_METHODS
        self.allow_headers = settings.CORS_ALLOW_HEADERS
        self.expose_headers = settings.CORS_EXPOSE_HEADERS
        self.max_age = settings.CORS_MAX_AGE

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http" or not settings.CORS_ENABLED:
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        origin = request.headers.get("origin", "")

        # Не CORS запрос (нет Origin)
        if not origin:
            await self.app(scope, receive, send)
            return

        # Preflight
        if request.method.upper() == "OPTIONS" and "access-control-request-method" in request.headers:
            # Private Network Access policy (опционально отклоняем)
            if settings.CORS_BLOCK_PRIVATE_NETWORK and request.headers.get("access-control-request-private-network") == "true":
                await self._send_403(send, reason=b"private_network_blocked")
                return

            if not _should_allow_origin(origin):
                await self._send_403(send)
                return

            acr_method = request.headers.get("access-control-request-method", "").upper()
            acr_headers_raw = request.headers.get("access-control-request-headers", "")
            acr_headers = [h.strip().lower() for h in acr_headers_raw.split(",") if h.strip()]

            # Разрешаем только объявленные методы/заголовки
            if acr_method and acr_method not in self.allow_methods:
                await self._send_403(send)
                return

            if acr_headers and not set(acr_headers).issubset(set(self.allow_headers)):
                await self._send_403(send)
                return

            headers = [
                (b"Content-Length", b"0"),
                (b"Access-Control-Allow-Methods", ", ".join(self.allow_methods).encode()),
                (b"Access-Control-Allow-Headers", ", ".join(self.allow_headers).encode()),
                (b"Access-Control-Max-Age", str(self.max_age).encode()),
            ]
            # Echo origin (без '*', особенно при credentials=true)
            headers.append((b"Access-Control-Allow-Origin", origin.encode()))
            _vary(headers, "Origin")
            _vary(headers, "Access-Control-Request-Method")
            _vary(headers, "Access-Control-Request-Headers")

            if self.allow_credentials:
                headers.append((b"Access-Control-Allow-Credentials", b"true"))

            # Для совместимости с прокси/кэшами — всегда 204 на preflight
            await send(
                {
                    "type": "http.response.start",
                    "status": status.HTTP_204_NO_CONTENT,
                    "headers": headers,
                }
            )
            await send({"type": "http.response.body", "body": b"", "more_body": False})
            return

        # Обычный CORS-запрос
        if not _should_allow_origin(origin):
            # Блокируем и не раскрываем информацию
            await self._send_403(send)
            return

        # Оборачиваем send для инъекции заголовков
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                # Echo origin
                headers.append((b"Access-Control-Allow-Origin", origin.encode()))
                _vary(headers, "Origin")

                if self.expose_headers:
                    headers.append((b"Access-Control-Expose-Headers", ", ".join(self.expose_headers).encode()))
                if self.allow_credentials:
                    headers.append((b"Access-Control-Allow-Credentials", b"true"))

                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)

    async def _send_403(self, send: Send, reason: bytes = b"cors_forbidden"):
        headers = [(b"Content-Type", b"text/plain; charset=utf-8")]
        _vary(headers, "Origin")
        await send(
            {
                "type": "http.response.start",
                "status": status.HTTP_403_FORBIDDEN,
                "headers": headers,
            }
        )
        await send({"type": "http.response.body", "body": reason, "more_body": False})


# =============================================================================
# Хелперы подключения
# =============================================================================

def add_cors_middleware(app) -> None:
    """
    Подключает HardenedCORSMiddleware.
    Совместимо с уже установленными middleware (например, логированием/ratelimit).
    """
    # Важно добавлять CORS до пользовательских маршрутов, но после request-id/логирования.
    app.add_middleware(HardenedCORSMiddleware)


# =============================================================================
# Пример интеграции с server.py
# =============================================================================
# from engine_core.api.http.middleware.cors import add_cors_middleware
# add_cors_middleware(app)
#
# ENV примеры:
#   ENGINE_CORS_ALLOW_CREDENTIALS=true
#   ENGINE_CORS_ALLOW_ORIGINS='["https://app.example.com","https://admin.example.com"]'
#   ENGINE_CORS_ALLOW_ORIGIN_WILDCARDS='["*.example.org"]'
#   ENGINE_CORS_ALLOW_ORIGIN_REGEXES='["^https://(.+\\.)?example\\.net(:\\d+)?$"]'
#   ENGINE_CORS_ALLOW_METHODS='["GET","POST","PUT","DELETE"]'
#   ENGINE_CORS_ALLOW_HEADERS='["authorization","content-type","x-request-id"]'
#   ENGINE_CORS_EXPOSE_HEADERS='["x-request-id"]'
#   ENGINE_CORS_MAX_AGE=86400
#   ENGINE_CORS_STRICT_HTTPS=true
#   ENGINE_CORS_BLOCK_PRIVATE_NETWORK=false
