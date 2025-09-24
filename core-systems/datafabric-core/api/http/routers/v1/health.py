# -*- coding: utf-8 -*-
"""
Health router for DataFabric HTTP API (FastAPI/Starlette).

Endpoints:
  GET /live   : process liveness (no dependencies)
  GET /ready  : service readiness (dependencies checked)
  GET /health : aggregated status (superset; for humans/tools)

Design:
  - Plugin-based async checks with per-check timeout and criticality.
  - Readiness cache to mitigate thundering herd.
  - Stable JSON schema for SRE tooling.
  - Proper HTTP codes: 200 OK or 503 Service Unavailable.
  - Safe headers (no-store) to avoid caching by proxies.
"""

from __future__ import annotations

import asyncio
import os
import platform
import socket
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Dict, List, Optional, Tuple

from fastapi import APIRouter, Response, status
from pydantic import BaseModel, Field

# ------------------------------------------------------------------------------
# Build/Runtime metadata
# ------------------------------------------------------------------------------

START_TIME_MONO = time.monotonic()
START_TIME_UNIX = int(time.time())

APP_NAME = os.getenv("APP_NAME", "datafabric-core")
APP_VERSION = os.getenv("APP_VERSION", "0.0.0")
GIT_SHA = os.getenv("GIT_SHA", "unknown")
BUILD_DATE = os.getenv("BUILD_DATE", "")
ENVIRONMENT = os.getenv("ENVIRONMENT", "dev")
REGION = os.getenv("REGION", os.getenv("K8S_REGION", "local"))
POD_NAME = os.getenv("POD_NAME", socket.gethostname())
POD_NAMESPACE = os.getenv("POD_NAMESPACE", "")
POD_IP = os.getenv("POD_IP", "")

# Readiness cache (seconds)
READY_CACHE_TTL = float(os.getenv("HEALTH_READY_CACHE_TTL", "2.0"))
# Global per-check default timeout (seconds)
CHECK_TIMEOUT = float(os.getenv("HEALTH_CHECK_TIMEOUT", "1.5"))

# ------------------------------------------------------------------------------
# Check registry
# ------------------------------------------------------------------------------

CheckFn = Callable[[], Awaitable[Tuple[bool, str]]]

@dataclass(frozen=True)
class CheckSpec:
    name: str
    fn: CheckFn
    timeout_s: float = CHECK_TIMEOUT
    critical: bool = True  # critical checks affect readiness 200/503

class _Registry:
    def __init__(self) -> None:
        self._checks: Dict[str, CheckSpec] = {}

    def register(self, spec: CheckSpec) -> None:
        self._checks[spec.name] = spec

    def list(self) -> List[CheckSpec]:
        return list(self._checks.values())

CHECKS = _Registry()

# Example placeholder checks (disabled by default).
# Integrators register concrete checks in application startup:
#
# async def check_redis() -> tuple[bool, str]:
#     pong = await redis.ping()
#     return bool(pong), "ok" if pong else "no pong"
# CHECKS.register(CheckSpec(name="redis", fn=check_redis, timeout_s=0.5, critical=True))

# ------------------------------------------------------------------------------
# Models
# ------------------------------------------------------------------------------

class CheckResult(BaseModel):
    name: str
    ok: bool
    duration_ms: int
    message: str = ""

class HealthPayload(BaseModel):
    status: str = Field(..., description="pass|warn|fail")
    service: str = APP_NAME
    version: str = APP_VERSION
    git_sha: str = GIT_SHA
    build_date: str = BUILD_DATE
    env: str = ENVIRONMENT
    region: str = REGION
    pod: str = POD_NAME
    pod_namespace: str = POD_NAMESPACE
    pod_ip: str = POD_IP
    started_at: int = Field(START_TIME_UNIX, description="epoch seconds")
    uptime_s: int
    checks: List[CheckResult] = Field(default_factory=list)

# ------------------------------------------------------------------------------
# Router
# ------------------------------------------------------------------------------

router = APIRouter(prefix="/v1", tags=["health"])

def _no_store_headers(r: Response) -> None:
    r.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, proxy-revalidate"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    r.headers["Content-Type"] = "application/json; charset=utf-8"

async def _run_check(spec: CheckSpec) -> CheckResult:
    started = time.monotonic()
    try:
        ok, msg = await asyncio.wait_for(spec.fn(), timeout=spec.timeout_s)
        dur = int((time.monotonic() - started) * 1000)
        return CheckResult(name=spec.name, ok=bool(ok), duration_ms=dur, message=str(msg or ""))
    except asyncio.TimeoutError:
        dur = int((time.monotonic() - started) * 1000)
        return CheckResult(name=spec.name, ok=False, duration_ms=dur, message=f"timeout>{spec.timeout_s}s")
    except Exception as e:
        dur = int((time.monotonic() - started) * 1000)
        return CheckResult(name=spec.name, ok=False, duration_ms=dur, message=f"error:{e}")

# Readiness cache
_last_ready_ts: float = 0.0
_last_ready_payload: Optional[Tuple[HealthPayload, int]] = None  # (payload, http_status)

async def _evaluate_readiness() -> Tuple[HealthPayload, int]:
    # Cached fast‑path
    global _last_ready_ts, _last_ready_payload
    now = time.monotonic()
    if _last_ready_payload and (now - _last_ready_ts) < READY_CACHE_TTL:
        return _last_ready_payload

    # Run all checks concurrently
    specs = CHECKS.list()
    results = await asyncio.gather(*[_run_check(s) for s in specs], return_exceptions=False)

    # Status aggregation
    critical_failed = any((not r.ok) for r, s in zip(results, specs) if s.critical)
    warn_only = (not critical_failed) and any((not r.ok) for r in results if not next(s for s in specs if s.name == r.name).critical)

    status_text = "pass"
    http_status = status.HTTP_200_OK
    if critical_failed:
        status_text = "fail"
        http_status = status.HTTP_503_SERVICE_UNAVAILABLE
    elif warn_only:
        status_text = "warn"

    payload = HealthPayload(
        status=status_text,
        uptime_s=int(time.monotonic() - START_TIME_MONO),
        checks=results,
    )

    _last_ready_ts = now
    _last_ready_payload = (payload, http_status)
    return payload, http_status

@router.get("/live", response_model=HealthPayload, summary="Liveness probe (no dependencies)")
async def live(response: Response) -> HealthPayload:
    _no_store_headers(response)
    payload = HealthPayload(
        status="pass",
        uptime_s=int(time.monotonic() - START_TIME_MONO),
        checks=[
            CheckResult(name="process", ok=True, duration_ms=0, message=f"python {platform.python_version()}"),
        ],
    )
    return payload

@router.get("/ready", response_model=HealthPayload, summary="Readiness probe (dependencies)")
async def ready(response: Response) -> HealthPayload:
    _no_store_headers(response)
    payload, http_status = await _evaluate_readiness()
    response.status_code = http_status
    return payload

@router.get("/health", response_model=HealthPayload, summary="Aggregated health")
async def health(response: Response) -> HealthPayload:
    _no_store_headers(response)
    # liveness + readiness combined, prefer readiness code
    payload, http_status = await _evaluate_readiness()
    response.status_code = http_status
    return payload

# ------------------------------------------------------------------------------
# Utilities to register common checks (optional helpers)
# ------------------------------------------------------------------------------

async def check_disk_free(path: str = "/", min_bytes: int = 512 * 1024 * 1024) -> Tuple[bool, str]:
    """Local disk free space."""
    try:
        st = os.statvfs(path)
        free = st.f_bavail * st.f_frsize
        ok = free >= min_bytes
        return ok, f"free={free}B threshold={min_bytes}B"
    except Exception as e:
        return False, f"error:{e}"

def register_disk_check(path: str = "/", min_bytes: int = 512 * 1024 * 1024, critical: bool = True, name: str = "disk") -> None:
    async def _fn() -> Tuple[bool, str]:
        return await check_disk_free(path=path, min_bytes=min_bytes)
    CHECKS.register(CheckSpec(name=name, fn=_fn, timeout_s=0.2, critical=critical))

async def check_env_vars(required: List[str]) -> Tuple[bool, str]:
    missing = [k for k in required if not os.getenv(k)]
    ok = len(missing) == 0
    return ok, "ok" if ok else f"missing:{','.join(missing)}"

def register_env_check(required: List[str], critical: bool = True, name: str = "env") -> None:
    async def _fn() -> Tuple[bool, str]:
        return await check_env_vars(required)
    CHECKS.register(CheckSpec(name=name, fn=_fn, timeout_s=0.2, critical=critical))

# Register a basic default non-intrusive check
register_disk_check(path=os.getenv("HEALTH_DISK_PATH", "/"), min_bytes=int(os.getenv("HEALTH_DISK_MIN_BYTES", str(256 * 1024 * 1024))), critical=False)
register_env_check(required=[k for k in os.getenv("HEALTH_REQUIRED_ENV", "").split(",") if k.strip()], critical=True, name="env")
