# ledger-core/api/http/middleware/cors.py
from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Iterable, List, Optional, Pattern, Sequence, Set, Tuple

ASGIApp = Callable[[dict, Callable, Callable], Awaitable]

# ===========================
# Конфигурация
# ===========================

@dataclass(frozen=True)
class CorsConfig:
    # Явно разрешённые origin'ы, например: ["https://app.example.com", "https://admin.example.com"]
    allow_origins: Tuple[str, ...] = field(default_factory=tuple)
    # Подстановки вида "*.example.com" (только поддомены), и/или regex
    allow_origin_wildcards: Tuple[str, ...] = field(default_factory=tuple)
    allow_origin_regexes: Tuple[Pattern[str], ...] = field(default_factory=tuple)

    # HTTP методы и заголовки
    allow_methods: Tuple[str, ...] = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
    allow_headers: Tuple[str, ...] = ("Authorization", "Content-Type", "Accept", "Origin")
    expose_headers: Tuple[str, ...] = ("X-Request-Id",)
    allow_credentials: bool = False

    # Preflight
    max_age_seconds: int = 600
    allow_private_network: bool = False  # Chrome PNA — Access-Control-Allow-Private-Network: true

    # Политика: отправлять ли заголовки CORS всегда (если Origin допустим), либо только при его наличии
    always_send: bool = True

    # Отладка/логирование
    log_denied: bool = True

    # Метрики (необязательные колбэки)
    on_preflight_allow: Optional[Callable[[str, str], None]] = None
    on_preflight_deny: Optional[Callable[[str, str, str], None]] = None
    on_actual_allow: Optional[Callable[[str, str], None]] = None
    on_actual_deny: Optional[Callable[[str, str, str], None]] = None


def _split_csv_env(val: str | None) -> Tuple[str, ...]:
    if not val:
        return tuple()
    return tuple(s.strip() for s in val.split(",") if s.strip())


def config_from_env(prefix: str = "LEDGER_CORS_") -> CorsConfig:
    """
    Читает конфигурацию из переменных окружения (безопасные дефолты):
      LEDGER_CORS_ALLOW_ORIGINS="https://app.example.com,https://admin.example.com"
      LEDGER_CORS_ALLOW_WILDCARDS="*.example.com,*.example.org"
      LEDGER_CORS_ALLOW_REGEXES="^https://([a-z0-9-]+)\\.example\\.com$"
      LEDGER_CORS_ALLOW_METHODS="GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS"
      LEDGER_CORS_ALLOW_HEADERS="Authorization,Content-Type,Accept,Origin"
      LEDGER_CORS_EXPOSE_HEADERS="X-Request-Id"
      LEDGER_CORS_ALLOW_CREDENTIALS="true"
      LEDGER_CORS_MAX_AGE_SECONDS="600"
      LEDGER_CORS_ALLOW_PRIVATE_NETWORK="false"
    """
    allow_origins = _split_csv_env(os.getenv(prefix + "ALLOW_ORIGINS"))
    allow_wildcards = _split_csv_env(os.getenv(prefix + "ALLOW_WILDCARDS"))
    regex_src = _split_csv_env(os.getenv(prefix + "ALLOW_REGEXES"))
    compiled = tuple(re.compile(p) for p in regex_src)

    allow_methods = _split_csv_env(os.getenv(prefix + "ALLOW_METHODS")) or ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
    allow_headers = _split_csv_env(os.getenv(prefix + "ALLOW_HEADERS")) or ("Authorization", "Content-Type", "Accept", "Origin")
    expose_headers = _split_csv_env(os.getenv(prefix + "EXPOSE_HEADERS")) or ("X-Request-Id",)

    allow_credentials = os.getenv(prefix + "ALLOW_CREDENTIALS", "false").lower() == "true"
    max_age = int(os.getenv(prefix + "MAX_AGE_SECONDS", "600"))
    allow_pna = os.getenv(prefix + "ALLOW_PRIVATE_NETWORK", "false").lower() == "true"

    return CorsConfig(
        allow_origins=tuple(allow_origins),
        allow_origin_wildcards=tuple(allow_wildcards),
        allow_origin_regexes=compiled,
        allow_methods=tuple(m.strip().upper() for m in allow_methods),
        allow_headers=tuple(h.strip() for h in allow_headers),
        expose_headers=tuple(expose_headers),
        allow_credentials=allow_credentials,
        max_age_seconds=max_age,
        allow_private_network=allow_pna,
    )


# ===========================
# Утилиты Origin‑проверки
# ===========================

def _normalize_origin(origin: str) -> str:
    # Убираем конечный слэш и понижаем регистр схемы/хоста; порт и схема остаются
    origin = origin.strip()
    return origin[:-1] if origin.endswith("/") else origin

def _hostport(origin: str) -> Tuple[str, Optional[int], Optional[str]]:
    # Грубый парсинг без urllib (избегаем зависимостей)
    # Возвращаем (host, port, scheme)
    m = re.match(r"^(?P<scheme>https?)://(?P<hostport>[^/]+)$", origin, re.IGNORECASE)
    if not m:
        return origin, None, None
    scheme = m.group("scheme").lower()
    hp = m.group("hostport")
    if ":" in hp:
        host, port_s = hp.rsplit(":", 1)
        try:
            port = int(port_s)
        except ValueError:
            port = None
        return host.lower(), port, scheme
    return hp.lower(), None, scheme

def _wildcard_match(origin: str, wc: str) -> bool:
    # "*.example.com" — соответствует foo.example.com, но не example.com
    if not wc.startswith("*."):
        return False
    host, _, _ = _hostport(origin)
    suffix = wc[1:].lower()  # ".example.com"
    return host.endswith(suffix) and host.count(".") > suffix.count(".")

def is_origin_allowed(origin: str, cfg: CorsConfig) -> bool:
    if not origin:
        return False
    origin = _normalize_origin(origin)

    # Точные совпадения
    if origin in cfg.allow_origins:
        return True

    # Подстановки по доменам
    for wc in cfg.allow_origin_wildcards:
        if _wildcard_match(origin, wc):
            return True

    # Regex
    for rx in cfg.allow_origin_regexes:
        if rx.search(origin):
            return True

    return False


# ===========================
# ASGI‑middleware
# ===========================

class DynamicCORSMiddleware:
    """
    ASGI CORS middleware с динамической проверкой Origin.
    Совместим с FastAPI/Starlette, но не зависит от них.
    """

    def __init__(self, app: ASGIApp, config: CorsConfig) -> None:
        self.app = app
        self.cfg = config
        # Precomputed заголовки
        self._allow_methods = ", ".join(sorted(set(self.cfg.allow_methods)))
        self._allow_headers = ", ".join(sorted({h for h in self.cfg.allow_headers}))
        self._expose_headers = ", ".join(sorted({h for h in self.cfg.expose_headers}))
        self._vary_preflight = b"Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
        self._vary_actual = b"Origin"

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        headers = _to_dict(scope.get("headers", []))
        origin = headers.get(b"origin", b"").decode("latin-1")
        method = scope.get("method", "")

        # Preflight
        if method.upper() == "OPTIONS" and b"access-control-request-method" in headers:
            await self._handle_preflight(origin, headers, send)
            return

        # Обычный запрос
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers_list = message.setdefault("headers", [])
                self._apply_actual_headers(headers_list, origin)
            await send(message)

        await self.app(scope, receive, send_wrapper)

    async def _handle_preflight(self, origin: str, headers: dict[bytes, bytes], send: Callable):
        acr_method = headers.get(b"access-control-request-method", b"").decode("latin-1").upper()
        acr_headers = headers.get(b"access-control-request-headers", b"").decode("latin-1")

        # В заголовке могут быть пробелы и произвольный регистр
        req_headers = tuple(h.strip() for h in acr_headers.split(",") if h.strip())

        allowed = (
            bool(origin)
            and is_origin_allowed(origin, self.cfg)
            and acr_method in self.cfg.allow_methods
            and all(self._header_allowed(h) for h in req_headers)
        )

        if not allowed:
            if self.cfg.log_denied and self.cfg.on_preflight_deny:
                self.cfg.on_preflight_deny(origin, acr_method, acr_headers)
            # Спецификация не требует отдавать 403 — можно 204 без CORS заголовков,
            # но для явности вернём 403.
            await send(
                {
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [
                        (b"content-length", b"0"),
                        (b"vary", self._vary_preflight),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": b""})
            return

        # Разрешённый preflight
        resp_headers: List[Tuple[bytes, bytes]] = [
            (b"vary", self._vary_preflight),
            (b"access-control-allow-origin", origin.encode("latin-1")),
            (b"access-control-allow-methods", self._allow_methods.encode("latin-1")),
            (b"access-control-max-age", str(self.cfg.max_age_seconds).encode("latin-1")),
        ]

        # В Access-Control-Allow-Headers нужно вернуть ровно то, что запросили,
        # либо полный список допустимых заголовков
        if req_headers:
            resp_headers.append(
                (b"access-control-allow-headers", ", ".join(req_headers).encode("latin-1"))
            )
        elif self._allow_headers:
            resp_headers.append((b"access-control-allow-headers", self._allow_headers.encode("latin-1")))

        if self.cfg.allow_credentials:
            resp_headers.append((b"access-control-allow-credentials", b"true"))

        # Private Network Access (Chrome)
        if self.cfg.allow_private_network and headers.get(b"access-control-request-private-network", b"").lower() == b"true":
            resp_headers.append((b"access-control-allow-private-network", b"true"))

        if self.cfg.on_preflight_allow:
            self.cfg.on_preflight_allow(origin, acr_method)

        await send(
            {
                "type": "http.response.start",
                "status": 204,
                "headers": resp_headers,
            }
        )
        await send({"type": "http.response.body", "body": b""})

    def _apply_actual_headers(self, headers_list: List[Tuple[bytes, bytes]], origin: str) -> None:
        if not origin:
            return
        if not is_origin_allowed(origin, self.cfg):
            if self.cfg.log_denied and self.cfg.on_actual_deny:
                self.cfg.on_actual_deny(origin, "ACTUAL", "")
            # Не добавляем CORS‑заголовки
            return

        # Установим Vary и CORS‑заголовки
        _append_header(headers_list, b"vary", self._vary_actual)
        _append_header(headers_list, b"access-control-allow-origin", origin.encode("latin-1"))
        if self.cfg.allow_credentials:
            _append_header(headers_list, b"access-control-allow-credentials", b"true")
        if self._expose_headers:
            _append_header(headers_list, b"access-control-expose-headers", self._expose_headers.encode("latin-1"))

        if self.cfg.on_actual_allow:
            self.cfg.on_actual_allow(origin, "ACTUAL")

    def _header_allowed(self, header_name: str) -> bool:
        # Спецификация допускает любое имя заголовка, если сервер так решил.
        # Мы сверяем по caseless.
        allowed = {h.lower() for h in self.cfg.allow_headers}
        return header_name.lower() in allowed


# ===========================
# Встраивание в приложение
# ===========================

def setup_cors(app: ASGIApp, config: Optional[CorsConfig] = None) -> ASGIApp:
    """
    Оборачивает существующий ASGI‑app CORS‑middleware'ом.
    Пример (FastAPI):
        app = FastAPI()
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=[...])
        app = setup_cors(app, config_from_env())
    """
    cfg = config or config_from_env()
    return DynamicCORSMiddleware(app, cfg)


# ===========================
# Низкоуровневые утилиты
# ===========================

def _to_dict(headers: Iterable[Tuple[bytes, bytes]]) -> dict[bytes, bytes]:
    d: dict[bytes, bytes] = {}
    for k, v in headers:
        # берём последний дубликат
        d[k.lower()] = v
    return d

def _append_header(headers: List[Tuple[bytes, bytes]], name: bytes, value: bytes) -> None:
    # Если уже есть Vary — объединяем корректно
    if name.lower() == b"vary":
        for i, (k, v) in enumerate(headers):
            if k.lower() == b"vary":
                merged = _merge_vary(v, value)
                headers[i] = (k, merged)
                return
    headers.append((name, value))

def _merge_vary(old: bytes, new: bytes) -> bytes:
    s_old = {p.strip().lower() for p in old.split(b",") if p.strip()}
    s_new = {p.strip().lower() for p in new.split(b",") if p.strip()}
    merged = sorted(s_old | s_new)
    return b", ".join(merged)
