"""
Hardened CORS middleware for physical-integration-core.

Особенности:
- Строгая проверка Origin: exact allowlist + regex allowlist.
- Безопасная работа с credentials: никогда не выдаёт "*" при allow_credentials=True.
- Корректные Vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers.
- Быстрый и корректный preflight (OPTIONS 204) с Access-Control-Allow-Private-Network (опционально).
- Блокировка неразрешённых кросс-оригин запросов (опционально 403).
- Поддержка null origin (file://, sandbox) только для доверенных рефереров.
- Метрики Prometheus (graceful при отсутствии prometheus_client).
- Прозрачное чтение конфигурации из переменных окружения (см. ENV ниже).

ENV (все опциональны):
  PIC_CORS_ALLOWED_ORIGINS              — CSV/JSON список точных origin (e.g. https://app.example.com,https://admin.example.com)
  PIC_CORS_ALLOWED_ORIGIN_REGEXES       — CSV/JSON список regex (e.g. ^https://([a-z0-9-]+\\.)?example\\.com(:\\d{1,5})?$)
  PIC_CORS_ALLOWED_METHODS              — CSV/JSON список методов (GET,POST,...). По умолчанию: GET,POST,PUT,PATCH,DELETE,OPTIONS
  PIC_CORS_ALLOWED_HEADERS              — CSV/JSON список заголовков (lower-case). "*" — отражать запрошенные. По умолчанию — список безопасных.
  PIC_CORS_EXPOSE_HEADERS               — CSV/JSON список заголовков ответа для expose. По умолчанию: X-Request-ID,Content-Length,Content-Disposition
  PIC_CORS_ALLOW_CREDENTIALS            — bool (default: true)
  PIC_CORS_MAX_AGE                      — int seconds (default: 600)
  PIC_CORS_BLOCK_DISALLOWED             — bool: 403 на кросс-оригин не из allowlist (default: false)
  PIC_CORS_ALLOW_NULL_ORIGIN            — bool: разрешить "null" только при доверенном Referer (default: false)
  PIC_CORS_TRUSTED_NULL_REFERERS        — CSV/JSON список доверенных Referer origin для "null"
  PIC_CORS_ALLOW_PRIVATE_NETWORK        — bool: отвечать Access-Control-Allow-Private-Network: true (default: false)
  PIC_CORS_METRICS_ENABLED              — bool (default: true)

Примечания:
- Никогда не используйте "*" вместе с credentials: middleware автоматически подставит конкретный origin при allow_credentials=True.
- Разрешённые заголовки сравниваются без регистра; "*" отражает запрошенные заголовки (безопасно при проверенном Origin).
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, PlainTextResponse

# --- Метрики Prometheus (graceful) ------------------------------------------------------------
try:
    from prometheus_client import Counter  # type: ignore
except Exception:  # pragma: no cover
    Counter = None  # type: ignore


def _parse_csv_or_json(value: Optional[str]) -> List[str]:
    if not value:
        return []
    v = value.strip()
    if not v:
        return []
    if v.startswith("["):
        try:
            data = json.loads(v)
            if isinstance(data, list):
                return [str(x).strip() for x in data if str(x).strip()]
        except Exception:
            pass
    # CSV / whitespace split
    parts = re.split(r"[,\s]+", v)
    return [p.strip() for p in parts if p.strip()]


def _to_lower_set(items: Iterable[str]) -> Set[str]:
    return {x.strip().lower() for x in items if x is not None and str(x).strip()}


def _compile_regex_list(patterns: Sequence[str]) -> List[re.Pattern]:
    compiled = []
    for p in patterns:
        try:
            compiled.append(re.compile(p))
        except re.error as e:
            logging.getLogger("pic.cors").warning("Invalid CORS regex '%s': %s", p, e)
    return compiled


@dataclass(frozen=True)
class CORSConfig:
    allowed_origins: Tuple[str, ...] = field(default_factory=tuple)
    allowed_origin_regexes: Tuple[re.Pattern, ...] = field(default_factory=tuple)
    allowed_methods: Tuple[str, ...] = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
    allowed_headers: Tuple[str, ...] = (
        "authorization",
        "content-type",
        "accept",
        "origin",
        "user-agent",
        "cache-control",
        "pragma",
        "x-request-id",
        "x-csrf-token",
        "x-forwarded-for",
        "x-forwarded-proto",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
    )
    expose_headers: Tuple[str, ...] = ("x-request-id", "content-length", "content-disposition")
    allow_credentials: bool = True
    max_age: int = 600
    block_disallowed: bool = False
    allow_null_origin: bool = False
    trusted_null_referers: Tuple[str, ...] = field(default_factory=tuple)
    allow_private_network: bool = False
    metrics_enabled: bool = True

    @staticmethod
    def from_env() -> "CORSConfig":
        allowed_origins = tuple(_parse_csv_or_json(os.getenv("PIC_CORS_ALLOWED_ORIGINS")))
        regexes = _compile_regex_list(_parse_csv_or_json(os.getenv("PIC_CORS_ALLOWED_ORIGIN_REGEXES")))
        allowed_methods = tuple(x.upper() for x in _parse_csv_or_json(os.getenv("PIC_CORS_ALLOWED_METHODS")) or
                                ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
        headers_raw = _parse_csv_or_json(os.getenv("PIC_CORS_ALLOWED_HEADERS"))
        allowed_headers = tuple(["*"] if headers_raw == ["*"] else sorted(_to_lower_set(headers_raw) or CORSConfig.allowed_headers))
        expose_headers = tuple(sorted(_to_lower_set(_parse_csv_or_json(os.getenv("PIC_CORS_EXPOSE_HEADERS"))) or CORSConfig.expose_headers))
        allow_credentials = os.getenv("PIC_CORS_ALLOW_CREDENTIALS", "true").lower() in ("1", "true", "yes")
        max_age = int(os.getenv("PIC_CORS_MAX_AGE", "600"))
        block_disallowed = os.getenv("PIC_CORS_BLOCK_DISALLOWED", "false").lower() in ("1", "true", "yes")
        allow_null_origin = os.getenv("PIC_CORS_ALLOW_NULL_ORIGIN", "false").lower() in ("1", "true", "yes")
        trusted_null_referers = tuple(_parse_csv_or_json(os.getenv("PIC_CORS_TRUSTED_NULL_REFERERS")))
        allow_private_network = os.getenv("PIC_CORS_ALLOW_PRIVATE_NETWORK", "false").lower() in ("1", "true", "yes")
        metrics_enabled = os.getenv("PIC_CORS_METRICS_ENABLED", "true").lower() in ("1", "true", "yes")

        return CORSConfig(
            allowed_origins=allowed_origins,
            allowed_origin_regexes=tuple(regexes),
            allowed_methods=allowed_methods,
            allowed_headers=allowed_headers,
            expose_headers=expose_headers,
            allow_credentials=allow_credentials,
            max_age=max_age,
            block_disallowed=block_disallowed,
            allow_null_origin=allow_null_origin,
            trusted_null_referers=trusted_null_referers,
            allow_private_network=allow_private_network,
            metrics_enabled=metrics_enabled,
        )


class HardenedCORSMiddleware(BaseHTTPMiddleware):
    """
    Промышленное CORS middleware. В отличие от стандартного,
    добавляет строгую проверку Origin, Private Network Access и метрики.
    """

    def __init__(self, app, config: Optional[CORSConfig] = None, logger: Optional[logging.Logger] = None) -> None:
        super().__init__(app)
        self.config = config or CORSConfig.from_env()
        self.log = logger or logging.getLogger("pic.cors")
        self._init_metrics()

        # Предрасчёт для быстрого membership
        self._allowed_exact = set(self.config.allowed_origins)
        self._allowed_methods = set(self.config.allowed_methods)
        self._allow_all_headers = tuple(self.config.allowed_headers) == ("*",)
        self._allowed_headers = set(h.lower() for h in self.config.allowed_headers) if not self._allow_all_headers else {"*"}

    # --- Metrics --------------------------------------------------------------
    def _init_metrics(self) -> None:
        self._m_req = None
        if Counter and self.config.metrics_enabled:
            try:
                # Ограничиваем кардинальность лейблов
                self._m_req = Counter(
                    "pic_cors_requests_total",
                    "CORS requests",
                    labelnames=("type", "allowed"),
                )
            except Exception:  # pragma: no cover
                self._m_req = None

    def _inc_metric(self, typ: str, allowed: bool) -> None:
        if self._m_req:
            try:
                self._m_req.labels(type=typ, allowed=str(bool(allowed)).lower()).inc()
            except Exception:
                pass

    # --- Helpers --------------------------------------------------------------
    @staticmethod
    def _get_header(req: Request, name: str) -> Optional[str]:
        val = req.headers.get(name)
        if val is None:
            return None
        return val.strip()

    @staticmethod
    def _add_vary(resp: Response, value: str) -> None:
        existing = resp.headers.get("Vary")
        if not existing:
            resp.headers["Vary"] = value
            return
        parts = {v.strip() for v in existing.split(",") if v.strip()}
        parts.add(value)
        resp.headers["Vary"] = ", ".join(sorted(parts))

    @staticmethod
    def _parse_origin(origin: str) -> Tuple[str, str, Optional[int]]:
        """Возвращает (scheme, host, port) или бросает ValueError."""
        parsed = urlsplit(origin)
        if not parsed.scheme or not parsed.hostname:
            raise ValueError("Invalid origin")
        port = parsed.port
        return parsed.scheme.lower(), parsed.hostname.lower(), port

    def _origin_allowed(self, origin: str, referer: Optional[str]) -> bool:
        if origin == "null":
            if not self.config.allow_null_origin:
                return False
            # Разрешаем "null" только при доверенном Referer (если задан)
            if self.config.trusted_null_referers:
                if not referer:
                    return False
                try:
                    r_scheme, r_host, r_port = self._parse_origin(referer)
                except ValueError:
                    return False
                ref = f"{r_scheme}://{r_host}" + (f":{r_port}" if r_port else "")
                return ref in set(self.config.trusted_null_referers)
            return True

        # Быстрый exact-match
        if origin in self._allowed_exact:
            return True

        # Regex allowlist
        for rx in self.config.allowed_origin_regexes:
            if rx.match(origin):
                return True

        return False

    def _reflect_allow_headers(self, requested: Sequence[str]) -> str:
        if self._allow_all_headers:
            # Отражаем запрошенные заголовки (нормализованные к lower-case)
            requested_norm = sorted({h.strip().lower() for h in requested if h.strip()})
            return ", ".join(requested_norm) if requested_norm else ""
        # Иначе — пересечение с разрешёнными
        allowed = sorted({h.strip().lower() for h in requested if h.strip() and h.strip().lower() in self._allowed_headers})
        return ", ".join(allowed) if allowed else ", ".join(sorted(self._allowed_headers))

    # --- Core dispatch --------------------------------------------------------
    async def dispatch(self, request: Request, call_next):
        origin = self._get_header(request, "Origin")
        referer = self._get_header(request, "Referer")

        if request.method.upper() == "OPTIONS" and origin is not None and self._get_header(request, "Access-Control-Request-Method"):
            # Preflight
            return await self._handle_preflight(request, origin, referer)

        # Non-preflight
        if origin is not None:
            allowed = self._origin_allowed(origin, referer)
            if not allowed and self.config.block_disallowed:
                self._inc_metric("actual", False)
                self.log.warning("Blocked CORS request from origin=%s path=%s", origin, request.url.path)
                return JSONResponse({"detail": "CORS origin not allowed"}, status_code=403)
            response: Response = await call_next(request)
            if allowed:
                self._apply_simple_cors_headers(response, origin)
                self._inc_metric("actual", True)
            else:
                self._inc_metric("actual", False)
            return response

        # No Origin — обычный same-origin / серверный вызов
        return await call_next(request)

    # --- Preflight ------------------------------------------------------------
    async def _handle_preflight(self, request: Request, origin: str, referer: Optional[str]) -> Response:
        req_method = self._get_header(request, "Access-Control-Request-Method") or ""
        req_headers = self._get_header(request, "Access-Control-Request-Headers") or ""
        req_headers_list = [h.strip() for h in req_headers.split(",")] if req_headers else []

        allowed_origin = self._origin_allowed(origin, referer)
        allowed_method = req_method.upper() in self._allowed_methods if req_method else False

        if not (allowed_origin and allowed_method):
            self._inc_metric("preflight", False)
            self.log.info(
                "Preflight denied: origin=%s allowed_origin=%s method=%s allowed_method=%s path=%s",
                origin, allowed_origin, req_method, allowed_method, request.url.path
            )
            if self.config.block_disallowed:
                # Возвращаем 403 и Vary, чтобы кеши не ломались
                resp = JSONResponse({"detail": "CORS preflight not allowed"}, status_code=403)
                self._add_vary(resp, "Origin")
                self._add_vary(resp, "Access-Control-Request-Method")
                self._add_vary(resp, "Access-Control-Request-Headers")
                return resp
            # Молчаливо 204 без заголовков CORS
            return Response(status_code=204)

        # Разрешено — формируем ответ
        allow_headers = self._reflect_allow_headers(req_headers_list)

        resp = Response(status_code=204)
        self._apply_preflight_headers(resp, origin, req_method.upper(), allow_headers, request)
        self._inc_metric("preflight", True)
        return resp

    # --- Header application ---------------------------------------------------
    def _apply_simple_cors_headers(self, response: Response, origin: str) -> None:
        # Никогда не возвращаем "*" при credentials
        response.headers["Access-Control-Allow-Origin"] = origin if self.config.allow_credentials else origin
        if self.config.allow_credentials:
            response.headers["Access-Control-Allow-Credentials"] = "true"
        if self.config.expose_headers:
            response.headers["Access-Control-Expose-Headers"] = ", ".join(self.config.expose_headers)
        # Корректный Vary
        self._add_vary(response, "Origin")

    def _apply_preflight_headers(
        self,
        response: Response,
        origin: str,
        method: str,
        allow_headers: str,
        request: Request,
    ) -> None:
        response.headers["Access-Control-Allow-Origin"] = origin if self.config.allow_credentials else origin
        if self.config.allow_credentials:
            response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = ", ".join(sorted(self._allowed_methods))
        if allow_headers:
            response.headers["Access-Control-Allow-Headers"] = allow_headers
        if self.config.max_age > 0:
            response.headers["Access-Control-Max-Age"] = str(self.config.max_age)

        # Private Network Access (при запросе браузера)
        if self.config.allow_private_network:
            pna = self._get_header(request, "Access-Control-Request-Private-Network")
            if pna and pna.lower() == "true":
                response.headers["Access-Control-Allow-Private-Network"] = "true"

        # Корректный Vary
        self._add_vary(response, "Origin")
        self._add_vary(response, "Access-Control-Request-Method")
        self._add_vary(response, "Access-Control-Request-Headers")


# --- Фабрика для удобного подключения ----------------------------------------------------------

def setup_hardened_cors(app, config: Optional[CORSConfig] = None, logger: Optional[logging.Logger] = None):
    """
    Подключение middleware:
        from fastapi import FastAPI
        app = FastAPI()
        setup_hardened_cors(app)  # или с CORSConfig.from_env()
    """
    app.add_middleware(HardenedCORSMiddleware, config=config or CORSConfig.from_env(), logger=logger)


# --- Пример безопасных дефолтов (используются автоматически из env) ----------------------------

DEFAULT_ALLOWED_HEADERS_NOTE = """
Разрешённые заголовки по умолчанию включают:
authorization, content-type, accept, origin, user-agent, cache-control, pragma,
x-request-id, x-csrf-token, x-forwarded-for, x-forwarded-proto, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform.
Установите PIC_CORS_ALLOWED_HEADERS='*' для отражения любых запрошенных заголовков (не забывайте про allowlist Origin!).
""".strip()
