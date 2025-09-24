# neuroforge-core/api/http/server.py
# Industrial ASGI HTTP server for NeuroForge Core
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
import time
import types
import uuid
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

try:
    # pydantic v2
    from pydantic_settings import BaseSettings
except Exception:  # pragma: no cover
    # pydantic v1 fallback
    from pydantic import BaseSettings  # type: ignore

from pydantic import BaseModel, Field, NonNegativeInt, PositiveInt, ValidationError

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi import status as http_status
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.types import ASGIApp, Receive, Scope, Send

# Optional deps
try:
    import uvicorn
except Exception:  # pragma: no cover
    uvicorn = None

try:
    from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
except Exception:  # pragma: no cover
    Counter = Histogram = None  # type: ignore
    def generate_latest() -> bytes:  # type: ignore
        return b""
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4"

try:
    import httpx
except Exception:  # pragma: no cover
    httpx = None

try:
    import jwt  # PyJWT
    from jwt import PyJWKClient
except Exception:  # pragma: no cover
    jwt = None
    PyJWKClient = None  # type: ignore

try:
    import aioredis
except Exception:  # pragma: no cover
    aioredis = None


# --------------------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------------------
class Settings(BaseSettings):
    app_name: str = "neuroforge-inference"
    env: str = os.getenv("ENVIRONMENT", "dev")
    host: str = "0.0.0.0"
    port: int = int(os.getenv("NF_HTTP_PORT", "8080"))
    admin_port: int = int(os.getenv("NF_ADMIN_PORT", "9099"))
    cors_origins: List[str] = Field(default_factory=lambda: os.getenv("NF_CORS_ORIGINS", "*").split(","))
    cors_allow_credentials: bool = False
    cors_allowed_methods: List[str] = Field(default_factory=lambda: ["GET", "POST", "OPTIONS"])
    cors_allowed_headers: List[str] = Field(default_factory=lambda: ["Authorization", "Content-Type", "X-Request-Id"])
    trusted_hosts: List[str] = Field(default_factory=lambda: os.getenv("NF_TRUSTED_HOSTS", "*").split(","))
    trust_x_forwarded: bool = True

    request_max_bytes: int = int(os.getenv("NF_MAX_REQUEST_BYTES", str(10 * 1024 * 1024)))  # 10 MiB

    # Rate limiting
    rate_limit_enabled: bool = True
    rate_capacity_per_minute: int = int(os.getenv("NF_RL_CAPACITY_PER_MINUTE", "120"))
    rate_burst: int = int(os.getenv("NF_RL_BURST", "60"))
    redis_url: Optional[str] = os.getenv("REDIS_URL")

    # Auth
    auth_mode: str = os.getenv("NF_AUTH_MODE", "none")  # none|apiKey|jwt
    api_key_header: str = os.getenv("NF_API_KEY_HEADER", "X-API-Key")
    api_key_value: Optional[str] = os.getenv("NF_API_KEY")
    jwt_jwks_url: Optional[str] = os.getenv("NF_JWKS_URL")
    jwt_aud: Optional[str] = os.getenv("NF_JWT_AUD")
    jwt_iss: Optional[str] = os.getenv("NF_JWT_ISS")
    jwt_cache_ttl_sec: int = 300

    # Observability
    log_level: str = os.getenv("NF_LOG_LEVEL", "INFO")
    log_json: bool = True
    prometheus_enabled: bool = True
    otel_enabled: bool = os.getenv("NF_OTEL_ENABLED", "false").lower() == "true"

    # Uvicorn
    uvicorn_timeout_keep_alive: int = 60
    uvicorn_backlog: int = 2048
    uvicorn_workers: int = int(os.getenv("NF_UVICORN_WORKERS", "1"))
    uvicorn_proxy_headers: bool = True

    class Config:
        env_file = ".env"
        env_prefix = ""
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    return Settings()


# --------------------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------------------
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for k in ("request_id", "path", "method", "status", "latency_ms", "client_ip"):
            v = getattr(record, k, None)
            if v is not None:
                base[k] = v
        if record.exc_info:
            base["exc"] = self.formatException(record.exc_info)
        return json.dumps(base, ensure_ascii=False)


def setup_logging(settings: Settings) -> None:
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(root.level)
    if settings.log_json:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root.addHandler(handler)


logger = logging.getLogger("neuroforge.http")


# --------------------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------------------
if Counter and Histogram:
    HTTP_REQUESTS = Counter(
        "nf_http_requests_total", "HTTP requests", ["method", "path", "status"]
    )
    HTTP_LATENCY = Histogram(
        "nf_http_request_duration_ms", "HTTP request duration (ms)", ["method", "path"],
        buckets=(10, 25, 50, 100, 250, 500, 1000, 2500, 5000)
    )
else:  # pragma: no cover
    HTTP_REQUESTS = HTTP_LATENCY = None


# --------------------------------------------------------------------------------------
# Utilities
# --------------------------------------------------------------------------------------
def request_id_from_headers(headers: Dict[str, str]) -> str:
    rid = headers.get("x-request-id") or headers.get("x-correlation-id")
    return rid or str(uuid.uuid4())


def client_ip_from_headers(request: Request, settings: Settings) -> str:
    if settings.trust_x_forwarded:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()
    return request.client.host if request.client else "unknown"


# --------------------------------------------------------------------------------------
# Middleware: RequestID
# --------------------------------------------------------------------------------------
class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        req_id = request_id_from_headers(request.headers)
        request.state.request_id = req_id
        response: Response = await call_next(request)
        response.headers["X-Request-Id"] = req_id
        return response


# --------------------------------------------------------------------------------------
# Middleware: Max body size
# --------------------------------------------------------------------------------------
class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, max_bytes: int):
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > self.max_bytes:
            return JSONResponse(
                status_code=http_status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content=error_payload("request-too-large", "Request body too large", request)
            )
        return await call_next(request)


# --------------------------------------------------------------------------------------
# Rate limiting (token bucket)
# --------------------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, capacity_per_minute: int, burst: int, redis_url: Optional[str] = None):
        self.capacity = max(1, capacity_per_minute)
        self.burst = max(1, burst)
        self.redis_url = redis_url
        self._local_buckets: Dict[str, Tuple[float, float]] = {}  # ip -> (tokens, last_ts)
        self._lock = asyncio.Lock()
        self._redis = None

    async def start(self):
        if self.redis_url and aioredis:
            self._redis = await aioredis.from_url(self.redis_url, encoding="utf-8", decode_responses=True)
        return self

    async def stop(self):
        if self._redis:
            await self._redis.close()

    async def allow(self, key: str) -> bool:
        now = time.monotonic()
        rate_per_sec = self.capacity / 60.0
        if self._redis:
            # Redis token bucket
            lua = """
            local key = KEYS[1]
            local now = tonumber(ARGV[1])
            local rate = tonumber(ARGV[2])
            local burst = tonumber(ARGV[3])
            local ttl = tonumber(ARGV[4])
            local last_ts = tonumber(redis.call('HGET', key, 'ts') or now)
            local tokens = tonumber(redis.call('HGET', key, 'tokens') or burst)
            local delta = now - last_ts
            tokens = math.min(burst, tokens + delta * rate)
            local allowed = 0
            if tokens >= 1 then
              tokens = tokens - 1
              allowed = 1
            end
            redis.call('HSET', key, 'ts', now, 'tokens', tokens)
            redis.call('EXPIRE', key, ttl)
            return allowed
            """
            allowed = await self._redis.eval(lua, 1, f"nf:rl:{key}", now, rate_per_sec, self.burst, 120)
            return bool(int(allowed))
        # In-memory bucket
        async with self._lock:
            tokens, last = self._local_buckets.get(key, (float(self.burst), now))
            delta = now - last
            tokens = min(self.burst, tokens + delta * rate_per_sec)
            allowed = tokens >= 1.0
            if allowed:
                tokens -= 1.0
            self._local_buckets[key] = (tokens, now)
            return allowed


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, limiter: RateLimiter, enabled: bool):
        super().__init__(app)
        self.limiter = limiter
        self.enabled = enabled

    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)
        ip = client_ip_from_headers(request, get_settings())
        ok = await self.limiter.allow(ip)
        if not ok:
            return JSONResponse(
                status_code=http_status.HTTP_429_TOO_MANY_REQUESTS,
                content=error_payload("rate-limited", "Too many requests", request),
                headers={"Retry-After": "60"}
            )
        return await call_next(request)


# --------------------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------------------
class AuthContext(BaseModel):
    mode: str
    subject: Optional[str] = None
    scopes: List[str] = Field(default_factory=list)
    raw: Optional[Dict[str, Any]] = None


class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, settings: Settings):
        super().__init__(app)
        self.settings = settings
        self._jwks_client = None
        self._jwks_last = 0.0

    async def _get_jwks_client(self):
        if self.settings.auth_mode != "jwt":
            return None
        if not (jwt and PyJWKClient):
            raise HTTPException(http_status.HTTP_500_INTERNAL_SERVER_ERROR, "JWT dependencies not installed")
        now = time.monotonic()
        if self._jwks_client and (now - self._jwks_last) < self.settings.jwt_cache_ttl_sec:
            return self._jwks_client
        if not self.settings.jwt_jwks_url:
            raise HTTPException(http_status.HTTP_500_INTERNAL_SERVER_ERROR, "JWKS URL not configured")
        # PyJWKClient internally caches keys; we still refresh reference
        self._jwks_client = PyJWKClient(self.settings.jwt_jwks_url)  # type: ignore
        self._jwks_last = now
        return self._jwks_client

    async def dispatch(self, request: Request, call_next):
        ctx = await self._authenticate(request)
        request.state.auth = ctx
        return await call_next(request)

    async def _authenticate(self, request: Request) -> AuthContext:
        mode = self.settings.auth_mode.lower()
        if mode == "none":
            return AuthContext(mode="none")
        if mode == "apikey":
            token = request.headers.get(self.settings.api_key_header)
            if not token or token != (self.settings.api_key_value or ""):
                raise HTTPException(http_status.HTTP_401_UNAUTHORIZED, "API key required")
            return AuthContext(mode="apikey", subject="apikey")
        if mode == "jwt":
            auth = request.headers.get("authorization", "")
            if not auth.lower().startswith("bearer "):
                raise HTTPException(http_status.HTTP_401_UNAUTHORIZED, "Bearer token required")
            token = auth.split(" ", 1)[1]
            client = await self._get_jwks_client()
            try:
                signing_key = client.get_signing_key_from_jwt(token)  # type: ignore
                payload = jwt.decode(  # type: ignore
                    token,
                    signing_key.key,
                    algorithms=["RS256", "ES256", "RS512", "ES512"],
                    audience=self.settings.jwt_aud if self.settings.jwt_aud else None,
                    issuer=self.settings.jwt_iss if self.settings.jwt_iss else None,
                )
            except Exception as e:
                raise HTTPException(http_status.HTTP_401_UNAUTHORIZED, f"Invalid JWT: {e}")
            sub = payload.get("sub")
            scopes = payload.get("scope", "") or payload.get("scopes", [])
            if isinstance(scopes, str):
                scopes = scopes.split()
            return AuthContext(mode="jwt", subject=sub, scopes=list(scopes), raw=payload)
        raise HTTPException(http_status.HTTP_500_INTERNAL_SERVER_ERROR, "Unsupported auth mode")


# --------------------------------------------------------------------------------------
# Error handling
# --------------------------------------------------------------------------------------
def error_payload(code: str, message: str, request: Optional[Request] = None, details: Any = None) -> Dict[str, Any]:
    rid = getattr(request.state, "request_id", None) if request else None
    return {
        "error": {"code": code, "message": message, "details": details},
        "request_id": rid,
    }


async def http_exception_handler(request: Request, exc: HTTPException):
    if HTTP_REQUESTS:
        HTTP_REQUESTS.labels(request.method, request.url.path, str(exc.status_code)).inc()
    return JSONResponse(
        status_code=exc.status_code,
        content=error_payload("http-error", exc.detail if isinstance(exc.detail, str) else str(exc.detail), request),
    )


async def validation_exception_handler(request: Request, exc: ValidationError):
    return JSONResponse(
        status_code=http_status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=error_payload("validation-error", "Invalid request", request, details=json.loads(exc.json())),
    )


# --------------------------------------------------------------------------------------
# Request logging + metrics
# --------------------------------------------------------------------------------------
class AccessLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except HTTPException as e:
            latency = (time.perf_counter() - start) * 1000
            extra = {
                "request_id": getattr(request.state, "request_id", None),
                "method": request.method,
                "path": request.url.path,
                "status": e.status_code,
                "latency_ms": int(latency),
                "client_ip": client_ip_from_headers(request, get_settings()),
            }
            logger.info("request", extra=extra)
            raise
        latency = (time.perf_counter() - start) * 1000
        if HTTP_REQUESTS and HTTP_LATENCY:
            HTTP_REQUESTS.labels(request.method, request.url.path, str(response.status_code)).inc()
            HTTP_LATENCY.labels(request.method, request.url.path).observe(latency)
        extra = {
            "request_id": getattr(request.state, "request_id", None),
            "method": request.method,
            "path": request.url.path,
            "status": response.status_code,
            "latency_ms": int(latency),
            "client_ip": client_ip_from_headers(request, get_settings()),
        }
        logger.info("request", extra=extra)
        return response


# --------------------------------------------------------------------------------------
# API models (minimal examples)
# --------------------------------------------------------------------------------------
class ChatMessage(BaseModel):
    role: str = Field(pattern="^(system|user|assistant)$")
    content: str


class ChatCompletionRequest(BaseModel):
    model: str
    messages: List[ChatMessage]
    max_new_tokens: PositiveInt = 256
    temperature: float = Field(ge=0.0, le=2.0, default=0.7)
    top_p: float = Field(ge=0.0, le=1.0, default=0.9)
    request_id: Optional[str] = None


class ChatCompletionChoice(BaseModel):
    index: int
    message: ChatMessage
    finish_reason: str


class ChatCompletionResponse(BaseModel):
    id: str
    model: str
    choices: List[ChatCompletionChoice]
    created: int
    usage: Dict[str, int]


class EmbeddingsRequest(BaseModel):
    model: str
    input: List[str]
    normalize: bool = True


class EmbeddingsResponse(BaseModel):
    model: str
    embeddings: List[List[float]]
    dim: PositiveInt


# --------------------------------------------------------------------------------------
# App factory
# --------------------------------------------------------------------------------------
def create_app(settings: Optional[Settings] = None) -> FastAPI:
    settings = settings or get_settings()
    setup_logging(settings)

    app = FastAPI(
        title=settings.app_name,
        version=os.getenv("NF_VERSION", "dev"),
        docs_url="/docs" if settings.env != "prod" else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.env != "prod" else None,
    )

    # Middlewares
    app.add_middleware(RequestIdMiddleware)
    app.add_middleware(AccessLogMiddleware)
    app.add_middleware(MaxBodySizeMiddleware, max_bytes=settings.request_max_bytes)
    app.add_middleware(GZipMiddleware, minimum_size=1024)

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in settings.cors_origins if o],
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=settings.cors_allowed_methods,
        allow_headers=settings.cors_allowed_headers,
    )
    # Trusted hosts
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=[h.strip() for h in settings.trusted_hosts if h])

    # Rate limiter
    limiter = RateLimiter(settings.rate_capacity_per_minute, settings.rate_burst, settings.redis_url)
    app.add_middleware(RateLimitMiddleware, limiter=limiter, enabled=settings.rate_limit_enabled)

    # Auth
    app.add_middleware(AuthMiddleware, settings=settings)

    # Exception handlers
    app.add_exception_handler(HTTPException, http_exception_handler)
    try:
        from fastapi.exception_handlers import request_validation_exception_handler as fastapi_validation_handler
        app.add_exception_handler(ValidationError, validation_exception_handler)
    except Exception:
        pass

    # Lifespan hooks
    @app.on_event("startup")
    async def _startup():
        await limiter.start()
        logger.info("server-startup", extra={"request_id": "-"})

        if settings.otel_enabled:
            try:
                # Minimal OTEL ASGI instrumentation (optional dependency)
                from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # type: ignore
                FastAPIInstrumentor.instrument_app(app)
                logger.info("otel-instrumented", extra={"request_id": "-"})
            except Exception as e:  # pragma: no cover
                logger.warning(f"otel-instrumentation-failed: {e}", extra={"request_id": "-"})

    @app.on_event("shutdown")
    async def _shutdown():
        await limiter.stop()
        logger.info("server-shutdown", extra={"request_id": "-"})

    # Admin/health
    @app.get("/healthz", include_in_schema=False)
    async def healthz():
        return PlainTextResponse("ok")

    @app.get("/readyz", include_in_schema=False)
    async def readyz():
        # Extend with actual dependency checks
        return PlainTextResponse("ready")

    if settings.prometheus_enabled:
        @app.get("/metrics", include_in_schema=False)
        async def metrics():
            data = generate_latest()
            return Response(content=data, media_type=CONTENT_TYPE_LATEST)

    # Routes (examples — replace with real handlers wired to your inference core)
    @app.post("/v1/chat/completions", response_model=ChatCompletionResponse)
    async def chat_completions(req: ChatCompletionRequest, request: Request, auth: AuthContext = Depends(lambda: request.state.auth)):
        # Example echo implementation; integrate with inference service here.
        if req.max_new_tokens > 4096:
            raise HTTPException(http_status.HTTP_400_BAD_REQUEST, "max_new_tokens too large")

        # Dummy response
        now = int(time.time())
        choice = ChatCompletionChoice(
            index=0,
            message=ChatMessage(role="assistant", content=f"Echo: {req.messages[-1].content}"),
            finish_reason="stop",
        )
        usage = {"prompt_tokens": sum(len(m.content) for m in req.messages), "completion_tokens": 10, "total_tokens": 10}
        return ChatCompletionResponse(
            id=str(uuid.uuid4()),
            model=req.model,
            choices=[choice],
            created=now,
            usage=usage,
        )

    @app.post("/v1/embeddings", response_model=EmbeddingsResponse)
    async def embeddings(req: EmbeddingsRequest, request: Request, auth: AuthContext = Depends(lambda: request.state.auth)):
        # Dummy embeddings (do not use in prod)
        dim = int(os.getenv("NF_EMB_DIM", "8"))
        out: List[List[float]] = []
        for text in req.input:
            seed = sum(ord(c) for c in text) % 9973
            vec = [((seed * (i + 1)) % 101) / 100.0 for i in range(dim)]
            if req.normalize:
                import math
                n = math.sqrt(sum(v * v for v in vec)) or 1.0
                vec = [v / n for v in vec]
            out.append(vec)
        return EmbeddingsResponse(model=req.model, embeddings=out, dim=dim)

    return app


# --------------------------------------------------------------------------------------
# Entrypoint
# --------------------------------------------------------------------------------------
def run() -> None:
    settings = get_settings()
    app = create_app(settings)

    if not uvicorn:
        raise RuntimeError("uvicorn is not installed")

    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        proxy_headers=settings.uvicorn_proxy_headers,
        forwarded_allow_ips="*" if settings.trust_x_forwarded else None,
        log_level=settings.log_level.lower(),
        timeout_keep_alive=settings.uvicorn_timeout_keep_alive,
        backlog=settings.uvicorn_backlog,
        workers=settings.uvicorn_workers,
        # http="h11",  # or "httptools" if installed
    )


if __name__ == "__main__":  # pragma: no cover
    run()
