# -*- coding: utf-8 -*-
"""
Admin Router v1 — operational endpoints for Omnimind.

Features:
- Strong API-key auth (constant-time compare), optional IP allowlist
- Per-key/IP token-bucket rate limiting
- Audit logging with request correlation
- Health/Ready endpoints (dependency-injected checks)
- Process stats (psutil optional)
- Safe config exposure (allowlist)
- Feature flags (in-memory with optional backend hook)
- Log level mutate (operate scope)
- Cache purge hook (operate scope)
- Reload/Shutdown hooks (danger scope)
- Optional metrics proxy passthrough
- Declarative dependency container for integrations

Python: 3.11+
FastAPI: >=0.110
"""

from __future__ import annotations

import asyncio
import dataclasses
import hmac
import logging
import os
import socket
import time
import types
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None  # Optional

# --------------------------------------------------------------------------------------
# Configuration & Dependency container
# --------------------------------------------------------------------------------------

class HealthReport(BaseModel):
    status: str = Field(..., description="overall status: ok|degraded|fail")
    checks: Dict[str, str] = Field(default_factory=dict)

class ReadyReport(BaseModel):
    status: str = Field(..., description="overall readiness: ready|starting|blocked")
    checks: Dict[str, str] = Field(default_factory=dict)

HealthCheck = Callable[[], Awaitable[HealthReport] | HealthReport]
ReadyCheck = Callable[[], Awaitable[ReadyReport] | ReadyReport]
PurgeFn = Callable[[], Awaitable[Dict[str, Any]] | Dict[str, Any]]
ReloadFn = Callable[[], Awaitable[Dict[str, Any]] | Dict[str, Any]]
ShutdownFn = Callable[[], Awaitable[Dict[str, Any]] | Dict[str, Any]]
QueueStatsFn = Callable[[], Awaitable[Dict[str, Any]] | Dict[str, Any]]
BroadcastFn = Callable[[str, Dict[str, Any]], Awaitable[None] | None]
MetricsFn = Callable[[], Awaitable[str] | str]

@dataclass(slots=True)
class AdminDeps:
    health_check: Optional[HealthCheck] = None
    ready_check: Optional[ReadyCheck] = None
    purge_cache: Optional[PurgeFn] = None
    hot_reload: Optional[ReloadFn] = None
    graceful_shutdown: Optional[ShutdownFn] = None
    queue_stats: Optional[QueueStatsFn] = None
    broadcaster: Optional[BroadcastFn] = None
    metrics_text: Optional[MetricsFn] = None  # prometheus text format
    safe_env_keys: Tuple[str, ...] = (
        "OMNIMIND_ENV",
        "OMNIMIND_VERSION",
        "GIT_SHA",
        "HOST",
        "PORT",
        "LOG_LEVEL",
        "OTEL_SERVICE_NAME",
    )

# --------------------------------------------------------------------------------------
# Security: API keys, scopes, allowlist
# --------------------------------------------------------------------------------------

@dataclass(slots=True)
class SecurityConfig:
    # Comma-separated API keys (plain); for higher security store hashed and compare with derived hash.
    admin_api_keys: Tuple[str, ...]
    # Optional mapping key -> scopes set (read, operate, danger)
    key_scopes: Dict[str, Tuple[str, ...]] | None = None
    # Optional IP allowlist (CIDRless exact matches or "*" to allow all)
    ip_allowlist: Tuple[str, ...] = ("*",)

def _ct_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))

def _resolve_key_scopes(cfg: SecurityConfig, provided_key: str) -> Tuple[str, ...]:
    if cfg.key_scopes and provided_key in cfg.key_scopes:
        return cfg.key_scopes[provided_key]
    # default scope
    return ("read", "operate")

# --------------------------------------------------------------------------------------
# Rate limiting: token bucket per (key, ip)
# --------------------------------------------------------------------------------------

class _TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int) -> None:
        if rate_per_sec <= 0 or burst <= 0:
            raise ValueError("rate_per_sec and burst must be > 0")
        self.rate = float(rate_per_sec)
        self.burst = int(burst)
        self.tokens = float(burst)
        self.last = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self.lock:
            now = time.monotonic()
            elapsed = now - self.last
            self.last = now
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            if self.tokens < 1.0:
                need = 1.0 - self.tokens
                delay = need / self.rate
                await asyncio.sleep(delay)
                now2 = time.monotonic()
                elapsed2 = now2 - self.last
                self.last = now2
                self.tokens = min(self.burst, self.tokens + elapsed2 * self.rate)
            self.tokens -= 1.0

class RateLimiter:
    def __init__(self, rps: float = 5.0, burst: int = 10) -> None:
        self.rps = rps
        self.burst = burst
        self._buckets: Dict[Tuple[str, str], _TokenBucket] = {}
        self._lock = asyncio.Lock()

    async def take(self, key: str, ip: str) -> None:
        idx = (key, ip)
        async with self._lock:
            bucket = self._buckets.get(idx)
            if bucket is None:
                bucket = _TokenBucket(self.rps, self.burst)
                self._buckets[idx] = bucket
        await bucket.acquire()

# --------------------------------------------------------------------------------------
# Context & dependencies
# --------------------------------------------------------------------------------------

class AdminContext(BaseModel):
    key: str
    scopes: Tuple[str, ...]
    ip: str
    req_id: str

def _client_ip(req: Request) -> str:
    # Prefer X-Forwarded-For first value if behind proxy, otherwise client.host
    xff = req.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return req.client.host if req.client else "unknown"

def security_gate(
    request: Request,
    x_admin_token: Optional[str] = Header(default=None, alias="X-Admin-Token"),
) -> AdminContext:
    keys_env = os.getenv("ADMIN_API_TOKENS", "").strip()
    if not keys_env:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Admin API disabled")
    cfg = SecurityConfig(
        admin_api_keys=tuple(k.strip() for k in keys_env.split(",") if k.strip()),
        ip_allowlist=tuple(s.strip() for s in os.getenv("ADMIN_IP_ALLOWLIST", "*").split(",") if s.strip()),
        key_scopes=None,  # can be bound in app state if needed
    )

    ip = _client_ip(request)
    if cfg.ip_allowlist != ("*",) and ip not in cfg.ip_allowlist:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="IP not allowed")

    token = x_admin_token or ""
    if not token or not any(_ct_equal(token, k) for k in cfg.admin_api_keys):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin token")

    scopes = _resolve_key_scopes(cfg, token)
    req_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    return AdminContext(key=token, scopes=scopes, ip=ip, req_id=req_id)

_rate_limiter = RateLimiter(rps=float(os.getenv("ADMIN_RPS", "5")), burst=int(os.getenv("ADMIN_BURST", "10")))

async def rate_limit(ctx: AdminContext = Depends(security_gate)) -> AdminContext:
    await _rate_limiter.take(ctx.key, ctx.ip)
    return ctx

# --------------------------------------------------------------------------------------
# Router
# --------------------------------------------------------------------------------------

router = APIRouter(prefix="/v1/admin", tags=["admin"])

# Shared feature flags (in-memory; optionally mirror via callback)
_FEATURE_FLAGS: Dict[str, bool] = {}
_FEATURE_LOCK = asyncio.Lock()

def _logger() -> logging.Logger:
    return logging.getLogger("omnimind.admin")

def _deps(request: Request) -> AdminDeps:
    # AdminDeps may be attached to app.state.admin_deps by the application.
    return getattr(request.app.state, "admin_deps", AdminDeps())

def _audit(event: str, ctx: AdminContext, extra: Optional[Mapping[str, Any]] = None) -> None:
    log = _logger()
    payload = dict(extra or {})
    payload.update({"event": event, "ip": ctx.ip, "req_id": ctx.req_id, "scopes": ",".join(ctx.scopes)})
    log.info("AUDIT %s", payload)

def _require_scope(ctx: AdminContext, needed: str) -> None:
    if needed not in ctx.scopes:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Missing scope: {needed}")

# --------------------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------------------

class LogLevelReq(BaseModel):
    level: str = Field(..., pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")

class FeatureFlagReq(BaseModel):
    key: str
    enabled: bool

class BroadcastReq(BaseModel):
    channel: str = Field(..., description="logical channel/topic name")
    payload: Dict[str, Any] = Field(default_factory=dict)

# --------------------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------------------

@router.get("/health", response_model=HealthReport)
async def health(
    ctx: AdminContext = Depends(rate_limit),
    deps: AdminDeps = Depends(_deps),
) -> HealthReport:
    _audit("health", ctx)
    if deps.health_check:
        rep = deps.health_check()
        if asyncio.iscoroutine(rep):
            rep = await rep  # type: ignore[assignment]
        return rep  # type: ignore[return-value]
    return HealthReport(status="ok", checks={"app": "ok"})

@router.get("/ready", response_model=ReadyReport)
async def ready(
    ctx: AdminContext = Depends(rate_limit),
    deps: AdminDeps = Depends(_deps),
) -> ReadyReport:
    _audit("ready", ctx)
    if deps.ready_check:
        rep = deps.ready_check()
        if asyncio.iscoroutine(rep):
            rep = await rep  # type: ignore[assignment]
        return rep  # type: ignore[return-value]
    return ReadyReport(status="ready", checks={"app": "ready"})

@router.get("/version")
async def version(ctx: AdminContext = Depends(rate_limit)) -> Dict[str, Any]:
    _audit("version", ctx)
    return {
        "service": os.getenv("OTEL_SERVICE_NAME", "omnimind-core"),
        "version": os.getenv("OMNIMIND_VERSION", "0.0.0"),
        "git_sha": os.getenv("GIT_SHA", ""),
        "python": os.getenv("PYTHON_VERSION", ""),
        "hostname": socket.gethostname(),
    }

@router.get("/config")
async def config(
    ctx: AdminContext = Depends(rate_limit),
    deps: AdminDeps = Depends(_deps),
) -> Dict[str, Any]:
    _audit("config", ctx)
    safe: Dict[str, Any] = {}
    for k in deps.safe_env_keys:
        if k in os.environ:
            safe[k] = os.environ[k]
    return safe

@router.post("/log-level")
async def set_log_level(
    req: LogLevelReq,
    ctx: AdminContext = Depends(rate_limit),
) -> Dict[str, Any]:
    _require_scope(ctx, "operate")
    _audit("log_level", ctx, {"level": req.level})
    level = getattr(logging, req.level)
    logging.getLogger().setLevel(level)
    for name in list(logging.Logger.manager.loggerDict.keys()):
        logging.getLogger(name).setLevel(level)
    return {"ok": True, "level": req.level}

@router.post("/cache/purge")
async def cache_purge(
    ctx: AdminContext = Depends(rate_limit),
    deps: AdminDeps = Depends(_deps),
) -> Dict[str, Any]:
    _require_scope(ctx, "operate")
    _audit("cache_purge", ctx)
    if not deps.purge_cache:
        return {"ok": False, "detail": "No purge handler configured"}
    res = deps.purge_cache()
    if asyncio.iscoroutine(res):
        res = await res  # type: ignore[assignment]
    return {"ok": True, "result": res}

@router.get("/stats")
async def stats(ctx: AdminContext = Depends(rate_limit)) -> Dict[str, Any]:
    _audit("stats", ctx)
    if psutil:
        p = psutil.Process()
        with p.oneshot():
            mem = p.memory_full_info().rss if hasattr(p, "memory_full_info") else p.memory_info().rss
            cpu = p.cpu_percent(interval=0.05)
            open_files = len(p.open_files())
            threads = p.num_threads()
        return {
            "pid": p.pid,
            "cpu_percent": cpu,
            "rss_bytes": mem,
            "open_files": open_files,
            "threads": threads,
            "uptime_sec": time.time() - p.create_time(),
        }
    # Fallback minimal
    return {"pid": os.getpid()}

@router.get("/queue")
async def queue_stats(
    ctx: AdminContext = Depends(rate_limit),
    deps: AdminDeps = Depends(_deps),
) -> Dict[str, Any]:
    _audit("queue_stats", ctx)
    if not deps.queue_stats:
        return {"ok": False, "detail": "No queue_stats handler configured"}
    res = deps.queue_stats()
    if asyncio.iscoroutine(res):
        res = await res  # type: ignore[assignment]
    return {"ok": True, "stats": res}

@router.get("/metrics", response_class=PlainTextResponse)
async def metrics(
    ctx: AdminContext = Depends(rate_limit),
    deps: AdminDeps = Depends(_deps),
) -> PlainTextResponse:
    _audit("metrics", ctx)
    if not deps.metrics_text:
        # Hide existence if not configured
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    text = deps.metrics_text()
    if asyncio.iscoroutine(text):
        text = await text  # type: ignore[assignment]
    return PlainTextResponse(text, media_type="text/plain; version=0.0.4")

@router.get("/features")
async def list_features(ctx: AdminContext = Depends(rate_limit)) -> Dict[str, Any]:
    _audit("features_list", ctx)
    # shallow copy
    async with _FEATURE_LOCK:
        flags = dict(_FEATURE_FLAGS)
    return {"flags": flags}

@router.post("/features")
async def set_feature(
    req: FeatureFlagReq,
    ctx: AdminContext = Depends(rate_limit),
) -> Dict[str, Any]:
    _require_scope(ctx, "operate")
    _audit("feature_set", ctx, {"key": req.key, "enabled": req.enabled})
    async with _FEATURE_LOCK:
        _FEATURE_FLAGS[req.key] = bool(req.enabled)
    return {"ok": True, "key": req.key, "enabled": _FEATURE_FLAGS[req.key]}

@router.post("/broadcast")
async def broadcast(
    req: BroadcastReq,
    ctx: AdminContext = Depends(rate_limit),
    deps: AdminDeps = Depends(_deps),
) -> Dict[str, Any]:
    _require_scope(ctx, "operate")
    _audit("broadcast", ctx, {"channel": req.channel})
    if not deps.broadcaster:
        return {"ok": False, "detail": "No broadcaster configured"}
    res = deps.broadcaster(req.channel, dict(req.payload))
    if asyncio.iscoroutine(res):
        await res  # type: ignore[func-returns-value]
    return {"ok": True}

@router.post("/reload")
async def reload_app(
    ctx: AdminContext = Depends(rate_limit),
    deps: AdminDeps = Depends(_deps),
) -> Dict[str, Any]:
    _require_scope(ctx, "danger")
    _audit("reload", ctx)
    if not deps.hot_reload:
        return {"ok": False, "detail": "No reload handler configured"}
    res = deps.hot_reload()
    if asyncio.iscoroutine(res):
        res = await res  # type: ignore[assignment]
    return {"ok": True, "result": res}

@router.post("/shutdown")
async def shutdown(
    ctx: AdminContext = Depends(rate_limit),
    deps: AdminDeps = Depends(_deps),
) -> Dict[str, Any]:
    _require_scope(ctx, "danger")
    _audit("shutdown", ctx)
    if not deps.graceful_shutdown:
        return {"ok": False, "detail": "No shutdown handler configured"}
    res = deps.graceful_shutdown()
    if asyncio.iscoroutine(res):
        res = await res  # type: ignore[assignment]
    return {"ok": True, "result": res}

# --------------------------------------------------------------------------------------
# Error handlers (unified JSON)
# --------------------------------------------------------------------------------------

@router.exception_handler(HTTPException)
async def _http_exc_handler(request: Request, exc: HTTPException):
    req_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    _logger().warning("HTTPException: %s req_id=%s", exc.detail, req_id)
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": str(exc.detail), "status": exc.status_code, "request_id": req_id},
    )

@router.exception_handler(Exception)
async def _unhandled_exc_handler(request: Request, exc: Exception):
    req_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    _logger().exception("Unhandled error req_id=%s", req_id)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "internal_error", "status": 500, "request_id": req_id},
    )

# --------------------------------------------------------------------------------------
# Wiring helper
# --------------------------------------------------------------------------------------

def mount_admin(app, deps: Optional[AdminDeps] = None) -> None:
    """
    Attach router and dependencies to FastAPI app.
    Example:
        from fastapi import FastAPI
        app = FastAPI()
        admin_deps = AdminDeps(health_check=my_health, ready_check=my_ready, purge_cache=my_purge, ...)
        mount_admin(app, admin_deps)
    """
    if deps is None:
        deps = AdminDeps()
    app.state.admin_deps = deps
    app.include_router(router)
