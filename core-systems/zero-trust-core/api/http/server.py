# zero-trust-core/api/http/server.py
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.middleware.gzip import GZipMiddleware
from starlette.types import ASGIApp

# ---------------------------
# Конфигурация приложения
# ---------------------------

@dataclass
class AppConfig:
    env: str = os.getenv("APP_ENV", "dev")  # dev|stage|prod
    cors_allow_origins: list[str] = field(
        default_factory=lambda: _split_csv(os.getenv("CORS_ALLOW_ORIGINS", ""))
    )
    cors_allow_methods: list[str] = field(
        default_factory=lambda: _split_csv(os.getenv("CORS_ALLOW_METHODS", "GET,POST,PUT,DELETE,OPTIONS"))
    )
    cors_allow_headers: list[str] = field(
        default_factory=lambda: _split_csv(os.getenv("CORS_ALLOW_HEADERS", "Authorization,Content-Type,X-Request-Id"))
    )
    cors_allow_credentials: bool = os.getenv("CORS_ALLOW_CREDENTIALS", "false").lower() == "true"

    rate_limit_rpm_default: int = int(os.getenv("RATE_LIMIT_RPM_DEFAULT", "600"))
    rate_limit_burst_default: int = int(os.getenv("RATE_LIMIT_BURST_DEFAULT", "200"))
    rate_limit_rpm_auth: int = int(os.getenv("RATE_LIMIT_RPM_AUTH", "120"))
    rate_limit_burst_auth: int = int(os.getenv("RATE_LIMIT_BURST_AUTH", "60"))

    mtls_enforce_from_proxy: bool = os.getenv("MTLS_ENFORCE_FROM_PROXY", "false").lower() == "true"
    mtls_verified_header: str = os.getenv("MTLS_VERIFIED_HEADER", "X-Client-Verified")
    mtls_subject_header: str = os.getenv("MTLS_SUBJECT_HEADER", "X-Client-Cert-Subject")

    log_level: str = os.getenv("LOG_LEVEL", "INFO")

def _split_csv(s: str) -> list[str]:
    return [x.strip() for x in s.split(",") if x.strip()]


# ---------------------------
# Наблюдаемость / логирование
# ---------------------------

class RequestIDMiddleware:
    def __init__(self, app: ASGIApp, header_name: str = "X-Request-Id") -> None:
        self.app = app
        self.header_name = header_name

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        # Вытаскиваем/создаём request-id
        headers = dict(scope.get("headers") or [])
        hdr = self.header_name.lower().encode()
        req_id = (headers.get(hdr) or b"").decode() or str(uuid.uuid4())
        scope["request_id"] = req_id

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers_list = [(k.lower(), v) for k, v in message.get("headers", [])]
                headers_list.append((self.header_name.encode().lower(), req_id.encode()))
                message["headers"] = headers_list
            await send(message)

        return await self.app(scope, receive, send_wrapper)


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))
                def set_header(name: str, value: str):
                    headers[name.encode().lower()] = value.encode()
                set_header("x-content-type-options", "nosniff")
                set_header("x-frame-options", "DENY")
                set_header("referrer-policy", "no-referrer")
                set_header("permissions-policy", "accelerometer=(),camera=(),microphone=()")
                message["headers"] = list(headers.items())
            await send(message)

        return await self.app(scope, receive, send_wrapper)


# ---------------------------
# Rate limit (встроенный in-memory токен‑бакет)
# ---------------------------

class TokenBucket:
    def __init__(self, rate_per_min: int, burst: int) -> None:
        self.capacity = max(1, burst)
        self.rate_per_sec = max(1, rate_per_min) / 60.0
        self.tokens = float(self.capacity)
        self.updated_at = time.monotonic()

    def allow(self) -> bool:
        now = time.monotonic()
        # пополняем
        elapsed = now - self.updated_at
        self.updated_at = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate_per_sec)
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class RateLimiter:
    def __init__(self, default_rpm: int, default_burst: int, auth_rpm: int, auth_burst: int) -> None:
        self.default = (default_rpm, default_burst)
        self.auth = (auth_rpm, auth_burst)
        self.buckets: dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()

    async def check(self, key: str, authenticated: bool) -> bool:
        rpm, burst = self.auth if authenticated else self.default
        async with self._lock:
            bucket = self.buckets.get(key)
            if bucket is None:
                bucket = TokenBucket(rpm, burst)
                self.buckets[key] = bucket
            return bucket.allow()


# ---------------------------
# Сервис токенов (интроспекция/ревокация)
# ---------------------------

@dataclass
class TokenStore:
    # revoked хранит только значения токенов для RFC7009
    revoked: set[str] = field(default_factory=set)

class TokenService:
    def __init__(self, store: TokenStore) -> None:
        self.store = store

    async def revoke(self, token: Optional[str]) -> bool:
        if not token:
            # RFC 7009 допускает no-op; возвращаем False как "нечего ревокать"
            return False
        if token in self.store.revoked:
            return True
        self.store.revoked.add(token)
        return True

    async def introspect(self, token: Optional[str]) -> Dict[str, Any]:
        # Минимально совместимо с RFC 7662 и вашей схемой: active=false, если токен неизвестен/ревокнут
        if not token or token in self.store.revoked:
            return {"active": False}
        # Здесь могла бы быть реальная проверка (подпись, exp, scope, aud и т.п.)
        # По умолчанию считаем неизвестный токен неактивным (безопаснее).
        return {"active": False}


# ---------------------------
# Зависимости/FastAPI
# ---------------------------

@dataclass
class AppState:
    cfg: AppConfig
    tokens: TokenService
    ratelimit: RateLimiter

def get_state(request: Request) -> AppState:
    return request.app.state.app_state  # type: ignore[attr-defined]


# ---------------------------
# Создание приложения
# ---------------------------

def create_app(cfg: Optional[AppConfig] = None) -> FastAPI:
    cfg = cfg or AppConfig()
    _setup_logging(cfg.log_level)

    app = FastAPI(
        title="zero-trust-core API",
        version=os.getenv("ZTC_API_VERSION", "1.0.0"),
        docs_url=os.getenv("DOCS_URL", "/docs" if cfg.env != "prod" else None),
        redoc_url=None,
        openapi_url="/openapi.json",
    )

    # Состояние/контейнер
    store = TokenStore()
    rl = RateLimiter(
        default_rpm=cfg.rate_limit_rpm_default,
        default_burst=cfg.rate_limit_burst_default,
        auth_rpm=cfg.rate_limit_rpm_auth,
        auth_burst=cfg.rate_limit_burst_auth,
    )
    app.state.app_state = AppState(cfg=cfg, tokens=TokenService(store), ratelimit=rl)  # type: ignore[attr-defined]

    # Middleware
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(GZipMiddleware, minimum_size=512)

    # CORS (при пустом списке — выключен)
    if cfg.cors_allow_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cfg.cors_allow_origins,
            allow_methods=cfg.cors_allow_methods or ["*"],
            allow_headers=cfg.cors_allow_headers or ["*"],
            allow_credentials=cfg.cors_allow_credentials,
            max_age=600,
        )

    # Обработчики ошибок
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(_: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "validation_error", "details": json.loads(exc.json())},
        )

    # Health/Ready
    @app.get("/healthz", tags=["meta"], response_class=PlainTextResponse)
    async def healthz():
        return "ok"

    @app.get("/readyz", tags=["meta"], response_class=PlainTextResponse)
    async def readyz():
        return "ready"

    # Простейшая проверка mTLS через заголовки от edge (опционально)
    async def _enforce_mtls(req: Request, cfg: AppConfig):
        if not cfg.mtls_enforce_from_proxy:
            return
        verified = req.headers.get(cfg.mtls_verified_header, "")
        if verified.upper() not in ("SUCCESS", "TRUE", "YES", "1"):
            raise HTTPException(status_code=401, detail="mTLS client verification required")
        # subject может использоваться для аудита/политик при желании
        _ = req.headers.get(cfg.mtls_subject_header)

    # Простая обвязка rate‑limit per IP / per auth endpoint
    async def _rate_limit(req: Request, state: AppState, is_auth_endpoint: bool) -> None:
        ip = _extract_ip(req)
        allowed = await state.ratelimit.check(ip, authenticated=is_auth_endpoint)
        if not allowed:
            raise HTTPException(status_code=429, detail="rate limit exceeded")

    # RFC 7009 — Token Revocation
    @app.post("/api/v1/revoke", tags=["oauth2"])
    async def revoke(
        request: Request,
        token: Optional[str] = Form(default=None),
        token_type_hint: Optional[str] = Form(default=None),  # не обязателен по RFC
        state: AppState = Depends(get_state),
    ):
        await _enforce_mtls(request, state.cfg)
        await _rate_limit(request, state, is_auth_endpoint=True)
        # Неверный контент‑тайп: FastAPI сам не распарсит json->Form, отдаст 422; приведём к 400/415
        if not request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
            # Контрактные тесты допускают 400 или 415
            return JSONResponse(status_code=415, content={"error": "unsupported_media_type"})
        await state.tokens.revoke(token)
        # Возвращаем 200 с пустым объектом — по контрактным тестам это допустимо
        return JSONResponse(status_code=200, content={})

    # OAuth2 Token Introspection (RFC 7662‑совместимо, минимально)
    @app.post("/api/v1/token/introspect", tags=["oauth2"])
    async def introspect(
        request: Request,
        token: Optional[str] = Form(default=None),
        token_type_hint: Optional[str] = Form(default=None),
        state: AppState = Depends(get_state),
    ):
        await _enforce_mtls(request, state.cfg)
        await _rate_limit(request, state, is_auth_endpoint=True)
        if not request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
            return JSONResponse(status_code=415, content={"error": "unsupported_media_type"})
        payload = await state.tokens.introspect(token)
        # Гарантируем application/json
        return JSONResponse(status_code=200, content=payload)

    return app


# Совместимость с импортами
def get_app() -> FastAPI:
    return create_app()

app = create_app()


# ---------------------------
# Вспомогательные функции
# ---------------------------

def _extract_ip(req: Request) -> str:
    # Пытаемся достать реальный клиентский IP (за прокси)
    xff = req.headers.get("x-forwarded-for", "")
    if xff:
        # берём первый адрес из списка
        first = xff.split(",")[0].strip()
        if _is_ip(first):
            return first
    rip = req.client.host if req.client else "0.0.0.0"
    return rip

def _is_ip(s: str) -> bool:
    return bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", s))

def _setup_logging(level: str) -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=lvl,
        format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}',
    )


# ---------------------------
# Запуск (uvicorn)
# ---------------------------

if __name__ == "__main__":
    import uvicorn  # опционально: uvicorn[standard]
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8080"))
    uvicorn.run("api.http.server:app", host=host, port=port, reload=os.getenv("RELOAD", "false") == "true")
