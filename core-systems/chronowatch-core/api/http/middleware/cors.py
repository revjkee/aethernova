# -*- coding: utf-8 -*-
"""
CORS middleware для chronowatch-core (ASGI, production-grade).

Особенности:
- Строгая проверка Origin: точные значения + regex (предкомпилированные).
- Безопасная обработка preflight (OPTIONS с Access-Control-Request-Method).
- Корректные заголовки Vary (Origin, Access-Control-Request-Method, Access-Control-Request-Headers).
- Поддержка credentials (и защита: не используем '*' при allow_credentials=True).
- Управление allow_methods/allow_headers/expose_headers/max_age.
- Опциональная поддержка Private Network Access (Access-Control-Allow-Private-Network).
- Быстрая и компактная реализация, без привязки к конкретному фреймворку.

Пример использования (FastAPI):
    from chronowatch_core.api.http.middleware.cors import CORSMiddleware, CORSConfig

    app = FastAPI()
    app.add_middleware(
        CORSMiddleware,
        config=CORSConfig(
            allowed_origins={"http://localhost:3000", "https://app.example.com"},
            allowed_origin_regexes=[r"^https://.*\\.example\\.org$"],
            allow_credentials=True,
            allow_methods={"GET","POST","PUT","PATCH","DELETE","OPTIONS"},
            allow_headers={"authorization","content-type","x-request-id"},
            expose_headers={"x-request-id","x-trace-id"},
            max_age=600,
            allow_private_network=False,
        ),
    )

Замечания:
- Если нужно разрешить все заголовки на preflight, укажите allow_headers={"*"}.
- Если хотите «любой origin» без credentials: allowed_origins={"*"}, allow_credentials=False.
- Если allow_credentials=True и allowed_origins={"*"}, будет выполнено безопасное «echo origin» с Vary: Origin.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Iterable, List, Mapping, MutableSequence, Optional, Pattern, Sequence, Set, Tuple

ASGIApp = Callable[[Mapping[str, Any], Callable[[], Awaitable[Mapping[str, Any]]], Callable[[Mapping[str, Any]], Awaitable[None]]], Awaitable[None]]


def _to_bytes(value: str) -> bytes:
    return value.encode("latin-1")


def _to_str(value: bytes) -> str:
    # заголовки HTTP ограничены ISO-8859-1 по стандарту
    return value.decode("latin-1")


def _get_header(headers: Sequence[Tuple[bytes, bytes]], name: str) -> Optional[str]:
    lname = name.lower().encode("latin-1")
    for k, v in headers:
        if k.lower() == lname:
            return _to_str(v).strip()
    return None


def _append_vary(headers: MutableSequence[Tuple[bytes, bytes]], values: Iterable[str]) -> None:
    # Корректно объединяем Vary, избегая дублей
    existing = None
    for idx, (k, v) in enumerate(headers):
        if k.lower() == b"vary":
            existing = (idx, {p.strip().lower() for p in _to_str(v).split(",") if p.strip()})
            break

    add = [v.strip() for v in values if v.strip()]
    if not add:
        return

    if existing is None:
        headers.append((b"vary", _to_bytes(", ".join(add))))
        return

    idx, present = existing
    for v in add:
        present.add(v.lower())
    headers[idx] = (b"vary", _to_bytes(", ".join(sorted(present))))


@dataclass(frozen=True)
class CORSConfig:
    allowed_origins: Set[str] = field(default_factory=set)         # {"https://app.example.com", "http://localhost:3000"} или {"*"}
    allowed_origin_regexes: List[Pattern[str]] = field(default_factory=list)  # [re.compile(r"..."), ...]
    allow_credentials: bool = False
    allow_methods: Set[str] = field(default_factory=lambda: {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
    allow_headers: Set[str] = field(default_factory=lambda: {"accept", "accept-language", "content-type", "authorization"})
    expose_headers: Set[str] = field(default_factory=set)
    max_age: int = 600  # seconds
    allow_private_network: bool = False  # Chrome PNA
    always_send: bool = False  # добавлять CORS даже без Origin (обычно False)

    def __post_init__(self) -> None:
        # Нормализация регистров
        object.__setattr__(self, "allow_methods", {m.upper() for m in self.allow_methods})
        object.__setattr__(self, "allow_headers", {h.lower() for h in self.allow_headers})
        object.__setattr__(self, "expose_headers", {h for h in self.expose_headers})
        # Предкомпилируем regexы, если они строковые
        compiled: List[Pattern[str]] = []
        for r in self.allowed_origin_regexes:
            compiled.append(re.compile(r.pattern if isinstance(r, re.Pattern) else str(r)))  # type: ignore
        object.__setattr__(self, "allowed_origin_regexes", compiled)

    @property
    def allow_all_origins(self) -> bool:
        return "*" in self.allowed_origins

    @property
    def allow_all_headers(self) -> bool:
        return "*" in self.allow_headers


class CORSMiddleware:
    def __init__(self, app: ASGIApp, config: CORSConfig) -> None:
        self.app = app
        self.cfg = config

    async def __call__(self, scope: Mapping[str, Any], receive: Callable[[], Awaitable[Mapping[str, Any]]], send: Callable[[Mapping[str, Any]], Awaitable[None]]) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        headers: Sequence[Tuple[bytes, bytes]] = scope.get("headers", [])
        method: str = scope.get("method", "GET").upper()

        origin = _get_header(headers, "origin")
        is_preflight = method == "OPTIONS" and _get_header(headers, "access-control-request-method") is not None

        # Ветка preflight (OPTIONS + Access-Control-Request-Method)
        if is_preflight:
            await self._handle_preflight(scope, receive, send, origin, headers)
            return

        # Обычный запрос: модифицируем ответ на этапе http.response.start
        async def send_with_cors(message: Mapping[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                h: List[Tuple[bytes, bytes]] = list(message.get("headers", []))
                self._apply_simple_cors(h, origin)
                message = dict(message)  # копия для модификации
                message["headers"] = h
            await send(message)

        # Если нет Origin и always_send=False — пропускаем без изменений
        await self.app(scope, receive, send_with_cors)

    def _origin_allowed(self, origin: Optional[str]) -> Tuple[bool, Optional[str]]:
        """
        Возвращает (allowed, value_for_allow_origin_header)
        value_for_allow_origin_header:
          - "*" если можно вернуть звездочку
          - конкретный origin если нужно эхо
          - None если не разрешено
        """
        if origin is None:
            return (self.cfg.always_send and self.cfg.allow_all_origins and not self.cfg.allow_credentials, "*" if (self.cfg.allow_all_origins and not self.cfg.allow_credentials) else None)

        # Безопасное сочетание '*' + credentials — используем echo origin с Vary
        if self.cfg.allow_all_origins:
            if self.cfg.allow_credentials:
                return True, origin
            return True, "*"

        # Точное совпадение
        if origin in self.cfg.allowed_origins:
            return True, origin

        # Разрешён ли "null" (например, file:// или sandboxed)
        if origin == "null" and "null" in self.cfg.allowed_origins:
            return True, "null"

        # Regex-совпадение
        for pattern in self.cfg.allowed_origin_regexes:
            if pattern.search(origin):
                return True, origin

        return False, None

    def _apply_simple_cors(self, headers_out: MutableSequence[Tuple[bytes, bytes]], origin: Optional[str]) -> None:
        allowed, allow_value = self._origin_allowed(origin)

        if not allowed or allow_value is None:
            # Ничего не добавляем (браузер заблокирует на клиенте)
            return

        # Allow-Origin
        headers_out.append((b"access-control-allow-origin", _to_bytes(allow_value)))

        # Vary обязательно, если возвращаем echo origin
        if allow_value != "*":
            _append_vary(headers_out, ["Origin"])

        # Credentials
        if self.cfg.allow_credentials:
            headers_out.append((b"access-control-allow-credentials", b"true"))

        # Expose-Headers
        if self.cfg.expose_headers:
            headers_out.append(
                (b"access-control-expose-headers", _to_bytes(", ".join(sorted(self.cfg.expose_headers))))
            )

    async def _handle_preflight(
        self,
        scope: Mapping[str, Any],
        receive: Callable[[], Awaitable[Mapping[str, Any]]],
        send: Callable[[Mapping[str, Any]], Awaitable[None]],
        origin: Optional[str],
        req_headers: Sequence[Tuple[bytes, bytes]],
    ) -> None:
        # Проверяем origin
        allowed, allow_value = self._origin_allowed(origin)
        if not allowed or allow_value is None:
            await self._deny_preflight(send, reason="origin_not_allowed")
            return

        # Проверяем запрошенный метод
        req_method = _get_header(req_headers, "access-control-request-method")
        if not req_method or req_method.upper() not in self.cfg.allow_methods:
            await self._deny_preflight(send, reason="method_not_allowed")
            return

        # Проверяем запрошенные заголовки
        req_hdrs_raw = _get_header(req_headers, "access-control-request-headers") or ""
        requested_headers: List[str] = [h.strip().lower() for h in req_hdrs_raw.split(",") if h.strip()]

        if not self.cfg.allow_all_headers:
            # Все запрошенные должны входить в allow_headers
            for h in requested_headers:
                if h not in self.cfg.allow_headers:
                    await self._deny_preflight(send, reason=f"header_not_allowed:{h}")
                    return

        # Формируем успешный preflight
        response_headers: List[Tuple[bytes, bytes]] = [
            (b"access-control-allow-origin", _to_bytes(allow_value)),
            (b"access-control-allow-methods", _to_bytes(", ".join(sorted(self.cfg.allow_methods)))),
            (b"access-control-max-age", _to_bytes(str(max(0, int(self.cfg.max_age))))),
        ]

        # Credentials
        if self.cfg.allow_credentials:
            response_headers.append((b"access-control-allow-credentials", b"true"))

        # Allow-Headers
        if self.cfg.allow_all_headers and requested_headers:
            # Эхо-заголовки, запрошенные браузером
            response_headers.append((b"access-control-allow-headers", _to_bytes(", ".join(requested_headers))))
        else:
            response_headers.append((b"access-control-allow-headers", _to_bytes(", ".join(sorted(self.cfg.allow_headers)))))

        # Private Network Access (Chrome)
        # Разрешаем только если явно включено и клиент запросил PNA
        pna_req = _get_header(req_headers, "access-control-request-private-network")
        if self.cfg.allow_private_network and pna_req and pna_req.lower() == "true":
            response_headers.append((b"access-control-allow-private-network", b"true"))

        # Правильные Vary
        vary_values = ["Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"]
        if allow_value != "*":
            # echo origin: Vary гарантирован
            pass
        _append_vary(response_headers, vary_values)

        # Отправляем 204 No Content
        await send(
            {
                "type": "http.response.start",
                "status": 204,
                "headers": response_headers,
            }
        )
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    async def _deny_preflight(self, send: Callable[[Mapping[str, Any]], Awaitable[None]], reason: str) -> None:
        # Явный отказ preflight. Можно сделать 403 с кратким описанием.
        headers = [
            (b"content-length", b"0"),
            (b"content-type", b"text/plain; charset=utf-8"),
        ]
        await send(
            {
                "type": "http.response.start",
                "status": 403,
                "headers": headers,
            }
        )
        await send({"type": "http.response.body", "body": b"", "more_body": False})
