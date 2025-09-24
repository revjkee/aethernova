# -*- coding: utf-8 -*-
"""
BlackVault Core REST Server
Промышленная версия: асинхронный FastAPI сервер с поддержкой Zero-Trust (mTLS, OIDC),
структурированных логов, OpenTelemetry и маршрутов для secrets/keys/policies/audit/health.
"""

import logging
import signal
import ssl
import sys
from pathlib import Path
from typing import Callable

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# --- Observability ---
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.logging import LoggingInstrumentor

# --- Local Handlers ---
from handlers import secrets, keys, policies, audit, health

# ---------------- Logging Setup ---------------- #
logger = logging.getLogger("blackvault.rest")
logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    level=logging.INFO,
)

# ---------------- App Factory ---------------- #
def create_app() -> FastAPI:
    app = FastAPI(
        title="BlackVault Core API",
        description="REST API для управления секретами, ключами, политиками и аудитом",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # CORS (опционально для UI)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # ограничить в prod
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Middleware для логов и трассировки
    @app.middleware("http")
    async def log_requests(request: Request, call_next: Callable) -> Response:
        logger.info("request_start", extra={"method": request.method, "url": str(request.url)})
        try:
            response = await call_next(request)
        except Exception as exc:
            logger.exception("unhandled_exception")
            return JSONResponse(
                status_code=500,
                content={"detail": "Internal Server Error"},
            )
        logger.info(
            "request_end",
            extra={"status": response.status_code, "path": request.url.path},
        )
        return response

    # Подключение маршрутов
    app.include_router(secrets.router, prefix="/v1/secrets", tags=["Secrets"])
    app.include_router(keys.router, prefix="/v1/keys", tags=["Keys"])
    app.include_router(policies.router, prefix="/v1/policies", tags=["Policies"])
    app.include_router(audit.router, prefix="/v1/audit", tags=["Audit"])
    app.include_router(health.router, prefix="/v1/health", tags=["Health"])

    # Инструментация (otel)
    try:
        FastAPIInstrumentor.instrument_app(app)
        LoggingInstrumentor().instrument(set_logging_format=True)
    except Exception as e:
        logger.warning("otel_instrumentation_failed", exc_info=e)

    return app


# ---------------- TLS Config ---------------- #
def build_ssl_context(cert_file: str, key_file: str, ca_file: str | None = None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    if ca_file:
        ctx.load_verify_locations(ca_file)
        ctx.verify_mode = ssl.CERT_REQUIRED  # enforce mTLS
    return ctx


# ---------------- Graceful Shutdown ---------------- #
def _setup_signals(server: uvicorn.Server):
    def _handle_sigterm(*_):
        logger.info("Received SIGTERM, shutting down gracefully...")
        server.should_exit = True

    signal.signal(signal.SIGTERM, _handle_sigterm)
    signal.signal(signal.SIGINT, _handle_sigterm)


# ---------------- Entrypoint ---------------- #
def main():
    cert_dir = Path("/etc/blackvault/tls")
    cert_file = cert_dir / "tls.crt"
    key_file = cert_dir / "tls.key"
    ca_file = cert_dir / "ca.pem"

    ssl_ctx = None
    if cert_file.exists() and key_file.exists():
        ssl_ctx = build_ssl_context(str(cert_file), str(key_file), str(ca_file) if ca_file.exists() else None)
        logger.info("TLS enabled", extra={"cert": str(cert_file), "ca": str(ca_file)})

    app = create_app()

    config = uvicorn.Config(
        app=app,
        host="0.0.0.0",
        port=8443,
        ssl=ssl_ctx,
        workers=1,
        log_level="info",
        timeout_keep_alive=30,
    )
    server = uvicorn.Server(config)
    _setup_signals(server)

    logger.info("Starting BlackVault REST API server...")
    server.run()


if __name__ == "__main__":
    sys.exit(main())
