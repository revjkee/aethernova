# human-sovereignty-core/webui/server/app.py
from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp

try:
    from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest  # type: ignore
except Exception:  # pragma: no cover
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"
    Counter = None
    Histogram = None
    generate_latest = None


@dataclass(frozen=True, slots=True)
class Settings:
    service_name: str
    environment: str
    bind_host: str
    bind_port: int

    cors_enabled: bool
    cors_allow_origins: tuple[str, ...]
    cors_allow_credentials: bool
    cors_allow_methods: tuple[str, ...]
    cors_allow_headers: tuple[str, ...]

    trusted_hosts_enabled: bool
    trusted_hosts: tuple[str, ...]

    gzip_enabled: bool
    gzip_minimum_size: int

    metrics_enabled: bool
    docs_enabled: bool
    openapi_enabled: bool

    request_id_header: str
    max_request_body_bytes: int

    auth_enabled: bool
    bearer_audience: str

    def as_public_dict(self) -> Dict[str, Any]:
        return {
            "service_name": self.service_name,
            "environment": self.environment,
            "bind_host": self.bind_host,
            "bind_port": self.bind_port,
            "cors_enabled": self.cors_enabled,
            "trusted_hosts_enabled": self.trusted_hosts_enabled,
            "gzip_enabled": self.gzip_enabled,
            "metrics_enabled": self.metrics_enabled,
            "docs_enabled": self.docs_enabled,
            "openapi_enabled": self.openapi_enabled,
            "request_id_header": self.request_id_header,
            "max_request_body_bytes": self.max_request_body_bytes,
            "auth_enabled": self.auth_enabled,
            "bearer_audience": self.bearer_audience,
        }


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    s = v.strip().lower()
    if s in ("1", "true", "yes", "y", "on"):
        return True
    if s in ("0", "false", "no", "n", "off"):
        return False
    raise ValueError(f"Invalid boolean env var {name}: {v!r}")


def _env_int(name: str, default: int, min_value: int = 0, max_value: int = 2**31 - 1) -> int:
    v = os.getenv(name)
    if v is None:
        return default
    try:
        n = int(v.strip())
    except Exception as exc:
        raise ValueError(f"Invalid int env var {name}: {v!r}") from exc
    if n < min_value or n > max_value:
        raise ValueError(f"Env var {name} out of range: {n}")
    return n


def _env_csv(name: str, default: str) -> tuple[str, ...]:
    v = os.getenv(name, default)
    items = [x.strip() for x in v.split(",") if x.strip()]
    return tuple(items)


def load_settings() -> Settings:
    service_name = os.getenv("HSC_WEBUI_SERVICE_NAME", "human-sovereignty-webui")
    environment = os.getenv("HSC_ENV", "dev").strip().lower()

    bind_host = os.getenv("HSC_WEBUI_BIND_HOST", "0.0.0.0")
    bind_port = _env_int("HSC_WEBUI_BIND_PORT", 8080, 1, 65535)

    cors_enabled = _env_bool("HSC_WEBUI_CORS_ENABLED", True)
    cors_allow_origins = _env_csv("HSC_WEBUI_CORS_ALLOW_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
    cors_allow_credentials = _env_bool("HSC_WEBUI_CORS_ALLOW_CREDENTIALS", True)
    cors_allow_methods = _env_csv("HSC_WEBUI_CORS_ALLOW_METHODS", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
    cors_allow_headers = _env_csv("HSC_WEBUI_CORS_ALLOW_HEADERS", "Authorization,Content-Type,X-Request-Id")

    trusted_hosts_enabled = _env_bool("HSC_WEBUI_TRUSTED_HOSTS_ENABLED", environment in ("staging", "prod"))
    trusted_hosts = _env_csv("HSC_WEBUI_TRUSTED_HOSTS", "localhost,127.0.0.1")

    gzip_enabled = _env_bool("HSC_WEBUI_GZIP_ENABLED", True)
    gzip_minimum_size = _env_int("HSC_WEBUI_GZIP_MIN_SIZE", 1024, 0, 10_000_000)

    metrics_enabled = _env_bool("HSC_WEBUI_METRICS_ENABLED", True)
    docs_enabled = _env_bool("HSC_WEBUI_DOCS_ENABLED", environment not in ("prod",))
    openapi_enabled = _env_bool("HSC_WEBUI_OPENAPI_ENABLED", True)

    request_id_header = os.getenv("HSC_WEBUI_REQUEST_ID_HEADER", "X-Request-Id").strip()
    if not request_id_header:
        raise ValueError("HSC_WEBUI_REQUEST_ID_HEADER must not be empty")

    max_request_body_bytes = _env_int("HSC_WEBUI_MAX_BODY_BYTES", 256_000, 1, 50_000_000)

    auth_enabled = _env_bool("HSC_WEBUI_AUTH_ENABLED", environment in ("staging", "prod"))
    bearer_audience = os.getenv("HSC_WEBUI_BEARER_AUD", "human-sovereignty-webui").strip()

    return Settings(
        service_name=service_name,
        environment=environment,
        bind_host=bind_host,
        bind_port=bind_port,
        cors_enabled=cors_enabled,
        cors_allow_origins=cors_allow_origins,
        cors_allow_credentials=cors_allow_credentials,
        cors_allow_methods=cors_allow_methods,
        cors_allow_headers=cors_allow_headers,
        trusted_hosts_enabled=trusted_hosts_enabled,
        trusted_hosts=trusted_hosts,
        gzip_enabled=gzip_enabled,
        gzip_minimum_size=gzip_minimum_size,
        metrics_enabled=metrics_enabled,
        docs_enabled=docs_enabled,
        openapi_enabled=openapi_enabled,
        request_id_header=request_id_header,
        max_request_body_bytes=max_request_body_bytes,
        auth_enabled=auth_enabled,
        bearer_audience=bearer_audience,
    )


class RequestIdMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, header_name: str) -> None:
        super().__init__(app)
        self._header_name = header_name

    async def dispatch(self, request: Request, call_next: Callable[[Request], Any]) -> Response:
        rid = request.headers.get(self._header_name) or str(uuid.uuid4())
        request.state.request_id = rid
        response: Response = await call_next(request)
        response.headers[self._header_name] = rid
        return response


class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        super().__init__(app)
        self._max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next: Callable[[Request], Any]) -> Response:
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > self._max_bytes:
                    return JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={"error": "payload_too_large", "max_bytes": self._max_bytes},
                    )
            except Exception:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"error": "invalid_content_length"},
                )
        return await call_next(request)


class AccessLogMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, service_name: str) -> None:
        super().__init__(app)
        self._service_name = service_name

    async def dispatch(self, request: Request, call_next: Callable[[Request], Any]) -> Response:
        start = time.time()
        response: Response
        try:
            response = await call_next(request)
        except Exception:
            raise
        finally:
            duration_ms = int((time.time() - start) * 1000)
            rid = getattr(request.state, "request_id", None)
            method = request.method
            path = request.url.path
            status_code = getattr(response, "status_code", 500) if "response" in locals() else 500
            _metrics_observe_request(method=method, path=path, status_code=status_code, duration_ms=duration_ms)
            _log_access(self._service_name, rid, method, path, status_code, duration_ms)
        return response


def _log_access(service: str, request_id: Optional[str], method: str, path: str, status_code: int, duration_ms: int) -> None:
    # Stdout JSON line for ingestion by log pipeline.
    payload = {
        "ts_unix": int(time.time()),
        "service": service,
        "request_id": request_id,
        "method": method,
        "path": path,
        "status": status_code,
        "duration_ms": duration_ms,
    }
    print(json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True))


_METRICS_READY = False
_REQ_COUNTER = None
_REQ_HIST = None


def _metrics_init(enabled: bool) -> None:
    global _METRICS_READY, _REQ_COUNTER, _REQ_HIST
    if not enabled:
        _METRICS_READY = False
        return
    if Counter is None or Histogram is None:
        _METRICS_READY = False
        return
    _REQ_COUNTER = Counter(
        "hsc_webui_http_requests_total",
        "Total HTTP requests",
        ["method", "path", "status"],
    )
    _REQ_HIST = Histogram(
        "hsc_webui_http_request_duration_ms",
        "HTTP request duration in milliseconds",
        ["method", "path", "status"],
        buckets=(5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000),
    )
    _METRICS_READY = True


def _metrics_observe_request(method: str, path: str, status_code: int, duration_ms: int) -> None:
    if not _METRICS_READY:
        return
    assert _REQ_COUNTER is not None
    assert _REQ_HIST is not None
    s = str(status_code)
    _REQ_COUNTER.labels(method=method, path=path, status=s).inc()
    _REQ_HIST.labels(method=method, path=path, status=s).observe(duration_ms)


def _error_response(
    *,
    request: Request,
    status_code: int,
    code: str,
    message: str,
    extra: Optional[Dict[str, Any]] = None,
) -> JSONResponse:
    rid = getattr(request.state, "request_id", None)
    body: Dict[str, Any] = {
        "error": code,
        "message": message,
        "request_id": rid,
    }
    if extra:
        body.update(extra)
    return JSONResponse(status_code=status_code, content=body)


async def _auth_dependency(
    request: Request,
    authorization: Optional[str] = Header(default=None, convert_underscores=False),
) -> None:
    cfg: Settings = request.app.state.settings
    if not cfg.auth_enabled:
        return
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing_bearer_token")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing_bearer_token")
    # Здесь должна быть проверка JWT (issuer, audience, exp, signature) через IAM.
    # В этой версии строго fail-closed: без валидатора токен считается недействительным.
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="token_validator_not_configured")


def create_app() -> FastAPI:
    settings = load_settings()
    _metrics_init(settings.metrics_enabled)

    docs_url = "/docs" if settings.docs_enabled else None
    redoc_url = "/redoc" if settings.docs_enabled else None
    openapi_url = "/openapi.json" if settings.openapi_enabled else None

    app = FastAPI(
        title="Human Sovereignty WebUI API",
        version="1.0.0",
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
    )

    app.state.settings = settings

    if settings.trusted_hosts_enabled:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.trusted_hosts))

    app.add_middleware(MaxBodySizeMiddleware, max_bytes=settings.max_request_body_bytes)
    app.add_middleware(RequestIdMiddleware, header_name=settings.request_id_header)
    app.add_middleware(AccessLogMiddleware, service_name=settings.service_name)

    if settings.gzip_enabled:
        app.add_middleware(GZipMiddleware, minimum_size=settings.gzip_minimum_size)

    if settings.cors_enabled:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.cors_allow_origins),
            allow_credentials=settings.cors_allow_credentials,
            allow_methods=list(settings.cors_allow_methods),
            allow_headers=list(settings.cors_allow_headers),
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        return _error_response(
            request=request,
            status_code=exc.status_code,
            code="http_error",
            message=str(exc.detail),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        return _error_response(
            request=request,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            code="validation_error",
            message="request_validation_failed",
            extra={"details": exc.errors()},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        return _error_response(
            request=request,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            code="internal_error",
            message="unhandled_exception",
        )

    @app.get("/healthz", response_class=PlainTextResponse, tags=["health"])
    async def healthz() -> str:
        return "ok"

    @app.get("/readyz", tags=["health"])
    async def readyz(request: Request) -> Dict[str, Any]:
        cfg: Settings = request.app.state.settings
        return {
            "ready": True,
            "settings": cfg.as_public_dict(),
        }

    @app.get("/metrics", tags=["observability"])
    async def metrics() -> Response:
        cfg: Settings = app.state.settings
        if not cfg.metrics_enabled:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="metrics_disabled")
        if generate_latest is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="prometheus_client_not_available")
        data = generate_latest()
        return Response(content=data, media_type=CONTENT_TYPE_LATEST)

    # Minimal API surface for WebUI.
    # Эти эндпоинты сделаны как каркас; бизнес-логика должна быть подключена из соответствующих модулей core.
    @app.get("/api/v1/me", tags=["auth"])
    async def me(_: None = Depends(_auth_dependency)) -> Dict[str, Any]:
        # В реальной интеграции сюда возвращается утверждённая IAM-идентичность.
        return {"authenticated": True}

    @app.get("/api/v1/approvals/pending", tags=["approvals"])
    async def approvals_pending(_: None = Depends(_auth_dependency)) -> Dict[str, Any]:
        # Подключить чтение очереди approvals из human-sovereignty-core.
        return {"items": [], "total": 0}

    @app.get("/api/v1/decision-packets/{packet_id}/diff", tags=["decision_packets"])
    async def decision_packet_diff(packet_id: str, _: None = Depends(_auth_dependency)) -> Dict[str, Any]:
        # Подключить diff_view.build_diff и рендер.
        return {"packet_id": packet_id, "diff": None}

    @app.post("/api/v1/execution/{execution_id}/rollback", tags=["execution"])
    async def trigger_rollback(execution_id: str, _: None = Depends(_auth_dependency)) -> Dict[str, Any]:
        # Подключить rollback executor.
        return {"execution_id": execution_id, "status": "requested"}

    return app


app = create_app()
