# policy-core/api/http/routers/v1/admin.py
# -*- coding: utf-8 -*-
from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Protocol, runtime_checkable

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

try:
    # опциональный трейсинг
    from opentelemetry import trace  # type: ignore
    _TRACER = trace.get_tracer("policy-core-admin")
except Exception:  # pragma: no cover
    _TRACER = None  # трейсинг не обязателен

log = logging.getLogger("policy_core.admin")
_START_TS = time.monotonic()
_START_AT = datetime.now(tz=timezone.utc)


# =========================
# Контракты интеграций (DI)
# =========================

class HealthStatus(BaseModel):
    component: str = Field(..., examples=["postgres"])
    status: Literal["pass", "warn", "fail"]
    latency_ms: float = Field(..., ge=0)
    detail: Optional[str] = None


class HealthReport(BaseModel):
    status: Literal["pass", "warn", "fail"]
    version: Optional[str] = None
    commit: Optional[str] = None
    started_at: datetime
    uptime_seconds: float = Field(..., ge=0)
    checks: List[HealthStatus] = Field(default_factory=list)


@runtime_checkable
class CacheService(Protocol):
    async def invalidate(self, key_pattern: str, scope: Literal["local", "global"] = "global") -> int: ...


@runtime_checkable
class PolicyService(Protocol):
    async def reload_bundle(self) -> Dict[str, Any]: ...
    async def current_revision(self) -> str: ...


@runtime_checkable
class SchedulerService(Protocol):
    async def run_job(self, name: str, args: Dict[str, Any] | None = None) -> Dict[str, Any]: ...


@runtime_checkable
class RateLimiterService(Protocol):
    async def reset(self, prefix: Optional[str] = None) -> int: ...


@runtime_checkable
class FeatureFlagsService(Protocol):
    async def list(self) -> Dict[str, bool]: ...
    async def set_many(self, flags: Dict[str, bool]) -> Dict[str, bool]: ...
    async def delete(self, names: List[str]) -> int: ...


@runtime_checkable
class AuditService(Protocol):
    async def export(self, kind: Literal["decision", "access", "admin"], since: Optional[datetime], until: Optional[datetime],
                     destination: str) -> Dict[str, Any]: ...


@runtime_checkable
class HealthChecker(Protocol):
    async def check(self) -> List[HealthStatus]: ...


@dataclass(frozen=True)
class AdminContext:
    cache: Optional[CacheService] = None
    policies: Optional[PolicyService] = None
    scheduler: Optional[SchedulerService] = None
    ratelimiter: Optional[RateLimiterService] = None
    flags: Optional[FeatureFlagsService] = None
    audit: Optional[AuditService] = None
    health: Optional[HealthChecker] = None


# ================
# Настройки/SEC
# ================

@dataclass(frozen=True)
class AdminSettings:
    api_prefix: str = "/api/v1/admin"
    # один или оба механизма: статический токен и/или JWT-клеймы со scope=admin:*
    admin_token: Optional[str] = None
    allow_jwt_admin_scope: bool = True
    redact_patterns: tuple[re.Pattern, ...] = (
        re.compile(r"(?i)(password|secret|token|api[_-]?key|authorization)"),
        re.compile(r"(?i)(private|secret).*key"),
    )


def _read_settings_from_env() -> AdminSettings:
    return AdminSettings(
        api_prefix=os.getenv("ADMIN_API_PREFIX", "/api/v1/admin"),
        admin_token=os.getenv("ADMIN_TOKEN"),
        allow_jwt_admin_scope=os.getenv("ADMIN_JWT_SCOPE", "true").lower() not in ("0", "false", "no"),
    )


# ======================
# Модели запросов/ответов
# ======================

class CacheInvalidateRequest(BaseModel):
    key_pattern: str = Field(..., min_length=1, description="Напр.: pc:dev:*")
    scope: Literal["local", "global"] = "global"


class CacheInvalidateResponse(BaseModel):
    invalidated: int


class FlagsUpsertRequest(BaseModel):
    flags: Dict[str, bool]


class FlagsDeleteRequest(BaseModel):
    names: List[str] = Field(..., min_items=1)


class FlagsResponse(BaseModel):
    flags: Dict[str, bool]


class JobRunRequest(BaseModel):
    name: str
    args: Optional[Dict[str, Any]] = None


class JobRunResponse(BaseModel):
    job_id: str
    status: Literal["enqueued", "started", "unknown"] = "enqueued"
    info: Dict[str, Any] = Field(default_factory=dict)


class BundleReloadResponse(BaseModel):
    revision: str
    info: Dict[str, Any] = Field(default_factory=dict)


class RateResetRequest(BaseModel):
    prefix: Optional[str] = None


class RateResetResponse(BaseModel):
    count: int


class AuditExportRequest(BaseModel):
    kind: Literal["decision", "access", "admin"]
    since: Optional[datetime] = None
    until: Optional[datetime] = None
    destination: str = Field(..., description="Напр.: s3://bucket/path.jsonl или file:///tmp/audit.jsonl")


class AuditExportResponse(BaseModel):
    task: Dict[str, Any]


class ConfigResponse(BaseModel):
    source: Literal["env", "runtime"]
    data: Dict[str, Any]


# ======================
# Безопасность и утилиты
# ======================

async def _require_admin(
    request: Request,
    settings: AdminSettings = Depends(lambda: _SETTINGS),
    x_admin_token: Optional[str] = Header(default=None, alias="X-Admin-Token"),
) -> None:
    # 1) Статический токен
    if settings.admin_token and x_admin_token and secrets_safe_compare(x_admin_token, settings.admin_token):
        request.state.is_admin = True
        return
    # 2) JWT-scope (если включено). Предполагается, что в middleware уже декодирован JWT в request.state.user
    if settings.allow_jwt_admin_scope:
        user = getattr(request.state, "user", None)
        scopes = set((user or {}).get("scopes") or (user or {}).get("scope", "").split())
        if "admin:*" in scopes or "admin:all" in scopes:
            request.state.is_admin = True
            return
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin privileges required")


def secrets_safe_compare(a: str, b: str) -> bool:
    # константное время
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a.encode(), b.encode()):
        result |= x ^ y
    return result == 0


def redact(obj: Any, patterns: tuple[re.Pattern, ...]) -> Any:
    # рекурсивная редакция ключей, похожих на секреты
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if any(p.search(str(k)) for p in patterns):
                out[k] = "***REDACTED***"
            else:
                out[k] = redact(v, patterns)
        return out
    if isinstance(obj, list):
        return [redact(v, patterns) for v in obj]
    return obj


# ======================
# Фабрика роутера
# ======================

_SETTINGS: AdminSettings = _read_settings_from_env()


def get_admin_router(ctx: AdminContext, settings: Optional[AdminSettings] = None) -> APIRouter:
    sett = settings or _SETTINGS
    router = APIRouter(prefix=sett.api_prefix, tags=["admin"])

    @router.get("/healthz", response_model=HealthReport, dependencies=[Depends(_require_admin)])
    async def healthz() -> HealthReport:
        span = _TRACER.start_as_current_span("admin.healthz") if _TRACER else _null_span()
        with span:
            checks: List[HealthStatus] = []
            if ctx.health:
                try:
                    checks = await ctx.health.check()
                except Exception as e:  # pragma: no cover
                    log.exception("health checker failed: %s", e)
                    checks.append(HealthStatus(component="health", status="fail", latency_ms=0.0, detail=str(e)))
            status_ = "pass"
            if any(c.status == "fail" for c in checks):
                status_ = "fail"
            elif any(c.status == "warn" for c in checks):
                status_ = "warn"
            report = HealthReport(
                status=status_, version=os.getenv("APP_VERSION"), commit=os.getenv("GIT_COMMIT"),
                started_at=_START_AT, uptime_seconds=time.monotonic() - _START_TS, checks=checks
            )
            return report

    @router.get("/readyz", response_model=Dict[str, str], dependencies=[Depends(_require_admin)])
    async def readyz() -> Dict[str, str]:
        # быстрый ready: достаточно, что bundle загружен и основной стор доступен
        if ctx.policies:
            try:
                _ = await ctx.policies.current_revision()
            except Exception as e:
                raise HTTPException(status_code=503, detail=f"policy service not ready: {e}")
        return {"status": "ready"}

    @router.post("/cache/invalidate", response_model=CacheInvalidateResponse, dependencies=[Depends(_require_admin)])
    async def cache_invalidate(body: CacheInvalidateRequest) -> CacheInvalidateResponse:
        if not ctx.cache:
            raise HTTPException(status_code=501, detail="cache service is not configured")
        start = time.perf_counter()
        count = await ctx.cache.invalidate(body.key_pattern, body.scope)
        log.info("cache invalidate pattern=%s scope=%s -> %d (%.1fms)", body.key_pattern, body.scope, count,
                 (time.perf_counter() - start) * 1000)
        return CacheInvalidateResponse(invalidated=count)

    @router.get("/feature-flags", response_model=FlagsResponse, dependencies=[Depends(_require_admin)])
    async def flags_list() -> FlagsResponse:
        if not ctx.flags:
            raise HTTPException(status_code=501, detail="feature flags service is not configured")
        return FlagsResponse(flags=await ctx.flags.list())

    @router.post("/feature-flags", response_model=FlagsResponse, dependencies=[Depends(_require_admin)])
    async def flags_upsert(body: FlagsUpsertRequest) -> FlagsResponse:
        if not ctx.flags:
            raise HTTPException(status_code=501, detail="feature flags service is not configured")
        return FlagsResponse(flags=await ctx.flags.set_many(body.flags))

    @router.delete("/feature-flags", response_model=Dict[str, int], dependencies=[Depends(_require_admin)])
    async def flags_delete(body: FlagsDeleteRequest) -> Dict[str, int]:
        if not ctx.flags:
            raise HTTPException(status_code=501, detail="feature flags service is not configured")
        deleted = await ctx.flags.delete(body.names)
        return {"deleted": deleted}

    @router.post("/jobs/run", response_model=JobRunResponse, dependencies=[Depends(_require_admin)])
    async def jobs_run(body: JobRunRequest) -> JobRunResponse:
        if not ctx.scheduler:
            raise HTTPException(status_code=501, detail="scheduler service is not configured")
        res = await ctx.scheduler.run_job(body.name, body.args)
        return JobRunResponse(job_id=str(res.get("id") or res.get("job_id") or "unknown"),
                              status=str(res.get("status") or "enqueued"),
                              info=res)

    @router.post("/policies/bundle/reload", response_model=BundleReloadResponse, dependencies=[Depends(_require_admin)])
    async def policies_reload() -> BundleReloadResponse:
        if not ctx.policies:
            raise HTTPException(status_code=501, detail="policy service is not configured")
        info = await ctx.policies.reload_bundle()
        rev = str(info.get("revision") or await ctx.policies.current_revision())
        return BundleReloadResponse(revision=rev, info=info)

    @router.post("/rate-limits/reset", response_model=RateResetResponse, dependencies=[Depends(_require_admin)])
    async def rate_limits_reset(body: RateResetRequest) -> RateResetResponse:
        if not ctx.ratelimiter:
            raise HTTPException(status_code=501, detail="rate limiter service is not configured")
        count = await ctx.ratelimiter.reset(body.prefix)
        return RateResetResponse(count=count)

    @router.post("/audit/export", response_model=AuditExportResponse, dependencies=[Depends(_require_admin)])
    async def audit_export(body: AuditExportRequest) -> AuditExportResponse:
        if not ctx.audit:
            raise HTTPException(status_code=501, detail="audit service is not configured")
        res = await ctx.audit.export(body.kind, body.since, body.until, body.destination)
        return AuditExportResponse(task=res)

    @router.get("/config", response_model=ConfigResponse, dependencies=[Depends(_require_admin)])
    async def config_view(source: Literal["env", "runtime"] = "env") -> ConfigResponse:
        # безопасная выдача: редакция секретов по ключам, а не значениям
        if source == "env":
            data = {k: v for k, v in os.environ.items() if k.startswith(("POLICY_CORE_", "APP_", "AWS_", "OTEL_"))}
        else:
            # от приложений ожидается, что они положат снэпшот в os.environ/или request.state.runtime_config
            data = getattr(asyncio.current_task(), "runtime_config", {}) or {}
        safe = redact(data, sett.redact_patterns)
        return ConfigResponse(source=source, data=safe)  # type: ignore[arg-type]

    @router.get("/ping", response_model=Dict[str, str], dependencies=[Depends(_require_admin)])
    async def ping(x_request_id: Optional[str] = Header(default=None, alias="X-Request-Id")) -> Dict[str, str]:
        return {"pong": "ok", "request_id": x_request_id or "n/a"}  # type: ignore[return-value]

    @router.exception_handler(Exception)  # type: ignore[arg-type]
    async def _unhandled_exc_handler(request: Request, exc: Exception):
        # единый обработчик на всякий случай
        log.exception("admin unhandled: %s", exc)
        return JSONResponse(status_code=500, content={"message": "internal server error", "code": "admin_internal_error"})

    return router


# ======================
# Вспомогательные объекты
# ======================

class _null_span:
    def __enter__(self): return self
    def __exit__(self, *a): return False
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False
