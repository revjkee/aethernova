"""FastAPI service exposing health, status, and Prometheus metrics."""

from __future__ import annotations

import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Response, status
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

from .core import ObservabilityCore

REQUESTS = Counter(
    "aethernova_observability_http_requests_total",
    "HTTP requests handled by Observability Core",
    ["method", "path", "status"],
)
REQUEST_DURATION = Histogram(
    "aethernova_observability_http_request_duration_seconds",
    "Observability Core HTTP request duration",
    ["method", "path"],
)

core = ObservabilityCore()


@asynccontextmanager
async def lifespan(_: FastAPI):
    await core.start()
    try:
        yield
    finally:
        await core.stop()


app = FastAPI(
    title="Aethernova Observability Core",
    version=core.config.version,
    lifespan=lifespan,
)


@app.middleware("http")
async def record_request_metrics(request: Request, call_next):
    started = time.perf_counter()
    response_status = 500
    try:
        response = await call_next(request)
        response_status = response.status_code
        return response
    finally:
        route = request.scope.get("route")
        path = getattr(route, "path", request.url.path)
        REQUESTS.labels(request.method, path, str(response_status)).inc()
        REQUEST_DURATION.labels(request.method, path).observe(time.perf_counter() - started)


@app.get("/health")
async def health() -> dict:
    return await core.health_check()


@app.get("/ready")
async def ready() -> dict[str, str]:
    health = await core.health_check()
    if not core.is_running or health["status"] != "healthy":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="observability core is not ready",
        )
    return {"status": "ready"}


@app.get("/status")
async def runtime_status() -> dict:
    return core.get_status()


@app.get("/metrics", include_in_schema=False)
async def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
