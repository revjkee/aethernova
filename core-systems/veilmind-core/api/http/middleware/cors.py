# -*- coding: utf-8 -*-
"""
Veilmind-core CORS middleware (ASGI)
Безопасные дефолты и промышленная реализация обработки CORS для ASGI-приложений.

Ключевые свойства:
- deny-by-default: без совпадения по allowlist/regex заголовки CORS НЕ выставляются;
- корректная обработка preflight (OPTIONS) с 204 и Vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers;
- исключает «отражённый CORS» (никогда не возвращает Origin, если он не разрешён);
- мягкая деградация: если заголовок Origin отсутствует, пропускает запрос без вмешательства;
- ограничение длины Origin/Request-Headers для DoS-защиты;
- поддержка allow_credentials с безопасной логикой (не сочетается с *).

Интеграция (FastAPI):
    from fastapi import FastAPI
    from veilmind_core.api.http.middleware.cors import CORSMiddleware, CORSConfig

    app = FastAPI()
    app.add_middleware(
        CORSMiddleware,
        config=CORSConfig(
            allow_origins=["https://app.example.com"],
            allow_origin_regexes=[r"^https://.+\\.trusted\\.example$"],
            allow_methods=["GET","POST","PUT","DELETE"],
            allow_headers=["Authorization","Content-Type","X-Request-ID"],
            expose_headers=["X-Request-ID"],
            allow_credentials=False,
            max_age=600,
            enabled=True,
        ),
    )

Совместимость: Python 3.9+, любая ASGI-библиотека (Starlette/FastAPI/Quart ASGI).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Pattern, Sequence, Tuple

from starlette.types import ASGIApp, Receive, Scope, Send, Message

__all__ = ["CORSConfig", "CORSMiddleware"]


@dataclass(frozen=True)
class CORSConfig:
    # Главный флаг — можно полностью отключить прослойку без снятия из стека
    enabled: bool = False

    # Разрешённые origins: точные значения и/или регулярные выражения
    allow_origins: Sequence[str] = field(default_factory=tuple)
    allow_origin_regexes: Sequence[str] = field(default_factory=tuple)

    # Разрешённые методы (для preflight) — в верхнем регистре
    allow_methods: Sequence[str] = field(
        default_factory=lambda: ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
    )
    # Разрешённые заголовки, пустой список => использовать пришедшие (но безопасно нормализованные)
    allow_headers: Sequence[str] = field(default_factory=tuple)

    # Какие заголовки можно экспонировать клиенту
    expose_headers: Sequence[str] = field(default_factory=tuple)

    # Разрешать ли cookies/авторизацию в кросс-доменных запросах
    allow_credentials: bool = False

    # Сколько кэшировать результат preflight (секунды)
    max_age: int = 600

    # Ограничения для защиты от злоупотреблений
    max_origin_length: int = 1024
    max_request_headers_length: int = 2048

    # Разрешать ли «*» для методов/заголовков в ответе preflight,
    # даже если allow_headers пуст — мы подставим пришедшие заголовки (нормализованные)
    wildcard_for_methods: bool = False

    # Явно разрешать все origins (не рекомендуется для prod). При True нагрузит '*' ТОЛЬКО когда allow_credentials=False.
    allow_all_origins: bool = False

    # Дополнительные пути, для которых CORS не применяется (например, /metrics)
    skip_paths: Sequence[str] = field(default_factory=lambda: ("/metrics", "/healthz", "/readyz"))

    def compile(self) -> "CompiledCORSConfig":
        regexes: List[Pattern[str]] = [re.compile(p) for p in self.allow_origin_regexes]
        methods = tuple({m.upper() for m in self.allow_methods})
        allow_headers = tuple({h.lower() for h in self.allow_headers})
        expose_headers = tuple({h for h in self.expose_headers})
        skips = tuple(self.skip_paths)
        return CompiledCORSConfig(
            enabled=self.enabled,
            allow_origins=tuple(self.allow_origins),
            allow_origin_regexes=tuple(regexes),
            allow_methods=methods,
            allow_headers=allow_headers,
            expose_headers=expose_headers,
            allow_credentials=self.allow_credentials,
            max_age=self.max_age,
            max_origin_length=self.max_origin_length,
            max_request_headers_length=self.max_request_headers_length,
            wildcard_for_methods=self.wildcard_for_methods,
            allow_all_origins=self.allow_all_origins,
            skip_paths=skips,
        )


@dataclass(frozen=True)
class CompiledCORSConfig:
    enabled: bool
    allow_origins: Tuple[str, ...]
    allow_origin_regexes: Tuple[Pattern[str], ...]
    allow_methods: Tuple[str, ...]
    allow_headers: Tuple[str, ...]
    expose_headers: Tuple[str, ...]
    allow_credentials: bool
    max_age: int
    max_origin_length: int
    max_request_headers_length: int
    wildcard_for_methods: bool
    allow_all_origins: bool
    skip_paths: Tuple[str, ...]


class CORSMiddleware:
    """
    Безопасная реализация CORS на уровне ASGI. Не отражает произвольные Origin.
    """

    def __init__(self, app: ASGIApp, config: CORSConfig) -> None:
        self.app = app
        self.cfg = config.compile()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self.cfg.enabled:
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "") or ""
        if any(path.startswith(skip) for skip in self.cfg.skip_paths):
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        origin = headers.get("origin")

        # Не CORS-запрос — пропускаем без изменений
        if not origin:
            await self.app(scope, receive, send)
            return

        # Базовая валидация Origin для защиты от DoS/злоумышленного ввода
        if len(origin) > self.cfg.max_origin_length or not self._valid_origin_syntax(origin):
            # Игнорируем CORS для странного Origin
            await self.app(scope, receive, send)
            return

        if scope.get("method", "GET").upper() == "OPTIONS" and headers.get("access-control-request-method"):
            await self._handle_preflight(scope, receive, send, origin, headers)
            return

        # Обычный CORS-запрос
        allowed, allow_origin_value = self._check_origin(origin)
        if not allowed:
            # Просто отдаём ответ приложения без CORS-заголовков
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers_list = list(message.get("headers", []))
                # Обязательные заголовки
                headers_list = _set_header(headers_list, b"access-control-allow-origin", allow_origin_value.encode())
                headers_list = _append_header(headers_list, b"vary", b"Origin")
                if self.cfg.allow_credentials and allow_origin_value != "*":
                    headers_list = _set_header(headers_list, b"access-control-allow-credentials", b"true")
                if self.cfg.expose_headers:
                    headers_list = _set_header(
                        headers_list,
                        b"access-control-expose-headers",
                        ",".join(self.cfg.expose_headers).encode(),
                    )
                message["headers"] = headers_list
            await send(message)

        await self.app(scope, receive, send_wrapper)

    async def _handle_preflight(self, scope: Scope, receive: Receive, send: Send, origin: str, headers: "Headers") -> None:
        method = headers.get("access-control-request-method", "").upper()
        req_headers_raw = headers.get("access-control-request-headers", "")

        # Ограничение размеров инпута
        if len(req_headers_raw) > self.cfg.max_request_headers_length:
            await _respond_204(send)  # молча, безопасная деградация
            return

        # Нормализация и дедупликация заголовков
        req_headers = _normalize_csv_header(req_headers_raw)

        allowed, allow_origin_value = self._check_origin(origin)
        if not allowed:
            # Не выставляем CORS заголовки, но отвечаем 204 (безопасно)
            await _respond_204(send)
            return

        # Проверка метода
        method_allowed = method in self.cfg.allow_methods or self.cfg.wildcard_for_methods
        if not method_allowed:
            await _respond_204(send)  # мягкая деградация
            return

        # Проверка заголовков (если allow_headers пуст — разрешаем присланные, но они уже нормализованы)
        if self.cfg.allow_headers:
            requested_not_allowed = [h for h in req_headers if h not in self.cfg.allow_headers]
            if requested_not_allowed:
                await _respond_204(send)
                return

        response_headers = [
            (b"access-control-allow-origin", allow_origin_value.encode()),
            (b"vary", b"Origin"),
            (b"vary", b"Access-Control-Request-Method"),
            (b"vary", b"Access-Control-Request-Headers"),
            (
                b"access-control-allow-methods",
                (",".join(self.cfg.allow_methods) if not self.cfg.wildcard_for_methods else "*").encode(),
            ),
            (
                b"access-control-allow-headers",
                (",".join(self.cfg.allow_headers) if self.cfg.allow_headers else ",".join(req_headers)).encode(),
            ),
            (b"access-control-max-age", str(self.cfg.max_age).encode()),
        ]

        if self.cfg.allow_credentials and allow_origin_value != "*":
            response_headers.append((b"access-control-allow-credentials", b"true"))

        await send(
            {
                "type": "http.response.start",
                "status": 204,
                "headers": response_headers,
            }
        )
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    def _check_origin(self, origin: str) -> Tuple[bool, str]:
        """
        Возвращает (allowed, allow-origin-value).
        Никогда не возвращает '*' вместе с allow_credentials=True (безопасность).
        """
        # Явно разрешены все origins?
        if self.cfg.allow_all_origins and not self.cfg.allow_credentials:
            return True, "*"

        # Точная проверка
        if origin in self.cfg.allow_origins:
            return True, origin

        # Regex‑проверка
        for rx in self.cfg.allow_origin_regexes:
            if rx.match(origin):
                return True, origin

        return False, ""

    @staticmethod
    def _valid_origin_syntax(origin: str) -> bool:
        # Простая, но строгая проверка: схема http/https, без пробелов/CRLF, без wildcard
        if "\r" in origin or "\n" in origin or " " in origin:
            return False
        if not (origin.startswith("http://") or origin.startswith("https://")):
            return False
        # Минимальная проверка хоста (символы и точка)
        return "://" in origin and "." in origin.split("://", 1)[1]


class Headers:
    """
    Утилита чтения заголовков из ASGI scope.
    """

    def __init__(self, scope: Scope) -> None:
        self._headers = scope.get("headers") or []

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        key_bytes = key.lower().encode()
        for k, v in self._headers:
            if k.lower() == key_bytes:
                try:
                    return v.decode()
                except Exception:
                    return default
        return default


def _normalize_csv_header(value: str) -> List[str]:
    """
    Нормализует CSV список заголовков:
    - разбивает по запятым;
    - тримит пробелы;
    - приводит к lower;
    - удаляет дубликаты, сохраняя порядок.
    """
    if not value:
        return []
    seen = set()
    out: List[str] = []
    for part in value.split(","):
        item = part.strip().lower()
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _set_header(headers: List[Tuple[bytes, bytes]], key: bytes, value: bytes) -> List[Tuple[bytes, bytes]]:
    key_l = key.lower()
    filtered = [(k, v) for k, v in headers if k.lower() != key_l]
    filtered.append((key, value))
    return filtered


def _append_header(headers: List[Tuple[bytes, bytes]], key: bytes, value: bytes) -> List[Tuple[bytes, bytes]]:
    headers.append((key, value))
    return headers


async def _respond_204(send: Send) -> None:
    await send({"type": "http.response.start", "status": 204, "headers": [(b"vary", b"Origin"), (b"vary", b"Access-Control-Request-Method"), (b"vary", b"Access-Control-Request-Headers")]})
    await send({"type": "http.response.body", "body": b"", "more_body": False})
