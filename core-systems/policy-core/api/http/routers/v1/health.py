# file: policy-core/api/http/routers/v1/health.py
from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from datetime import datetime, timezone

START_TIME_MONO = time.monotonic()
START_TIME_WALL = datetime.now(tz=timezone.utc)

router = APIRouter(prefix="/v1", tags=["health"])

# =========================
# Enums, models (proto-like)
# =========================

class ProbeKind(str, Enum):
    LIVENESS = "LIVENESS"
    READINESS = "READINESS"
    STARTUP = "STARTUP"


class ServingStatus(str, Enum):
    SERVING = "SERVING"
    NOT_SERVING = "NOT_SERVING"
    DEGRADED = "DEGRADED"
    MAINTENANCE = "MAINTENANCE"
    STARTING = "STARTING"
    STOPPING = "STOPPING"


class DependencyStatus(BaseModel):
    name: str
    status: ServingStatus
    latency: float = Field(0.0, description="Latency in seconds of last check")
    last_checked: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    last_error: Optional[Dict[str, Any]] = None
    endpoint: Optional[str] = None
    attributes: Dict[str, str] = Field(default_factory=dict)


class HealthCheckResponse(BaseModel):
    status: ServingStatus
    service: str = "policy-core"
    probe: ProbeKind
    checked_at: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    version: Optional[str] = None
    revision: Optional[str] = None
    node: Optional[str] = Field(default_factory=lambda: os.uname().nodename if hasattr(os, "uname") else None)
    region: Optional[str] = None
    dependencies: List[DependencyStatus] = Field(default_factory=list)
    diagnostics: Dict[str, str] = Field(default_factory=dict)
    outages_total: int = 0
    p95_latency_ms: Optional[float] = None
    p99_latency_ms: Optional[float] = None


class BuildInfo(BaseModel):
    version: str
    commit_sha: str
    vcs_url: Optional[str] = None
    build_time: Optional[datetime] = None
    runtime: Optional[str] = None
    features: List[str] = Field(default_factory=list)
    metadata: Dict[str, str] = Field(default_factory=dict)


class MetricsSummary(BaseModel):
    uptime_seconds: float
    cpu_utilization: Optional[float] = Field(None, description="0..1")
    rss_bytes: Optional[int] = None
    rps: float = 0.0


# =====================================
# Health checks registry & implementation
# =====================================

CheckFn = Callable[[], Awaitable[Tuple[ServingStatus, Optional[str], Dict[str, str]]]]
# Returns: (status, error_message_or_None, attributes)

@dataclass(frozen=True)
class DependencySpec:
    name: str
    fn: CheckFn
    critical: bool = True
    endpoint: Optional[str] = None
    timeout_s: float = 2.0
    attributes: Dict[str, str] = field(default_factory=dict)


class HealthRegistry:
    """
    Registry of dependency checks used by the health router.
    Attach an instance at app.state.health_registry during startup.
    """
    def __init__(self, specs: Iterable[DependencySpec] | None = None) -> None:
        self._specs: Dict[str, DependencySpec] = {}
        if specs:
            for s in specs:
                self._specs[s.name] = s

    def register(self, spec: DependencySpec) -> None:
        self._specs[spec.name] = spec

    def all(self) -> Mapping[str, DependencySpec]:
        return dict(self._specs)


async def _run_check(spec: DependencySpec) -> DependencyStatus:
    t0 = time.perf_counter()
    err: Optional[Dict[str, Any]] = None
    status: ServingStatus = ServingStatus.NOT_SERVING
    attrs: Dict[str, str] = dict(spec.attributes)

    try:
        status, error_text, extra_attrs = await asyncio.wait_for(spec.fn(), timeout=spec.timeout_s)
        attrs.update(extra_attrs or {})
        if error_text:
            err = {"code": "DEPENDENCY_ERROR", "message": error_text}
    except asyncio.TimeoutError:
        status = ServingStatus.NOT_SERVING
        err = {"code": "TIMEOUT", "message": f"Check timed out after {spec.timeout_s:.2f}s"}
    except Exception as ex:  # noqa: BLE001
        status = ServingStatus.NOT_SERVING
        err = {"code": "EXCEPTION", "message": str(ex.__class__.__name__), "detail": str(ex)}

    latency = time.perf_counter() - t0
    return DependencyStatus(
        name=spec.name,
        status=status,
        latency=latency,
        last_checked=datetime.now(tz=timezone.utc),
        last_error=err,
        endpoint=spec.endpoint,
        attributes=attrs,
    )


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(name)
    return v if v is not None else default


def _aggregate_status(
    probe: ProbeKind,
    deps: List[DependencyStatus],
    startup_complete: bool,
    maintenance_mode: bool,
) -> ServingStatus:
    # Maintenance overrides except for liveness
    if maintenance_mode and probe in (ProbeKind.READINESS, ProbeKind.STARTUP):
        return ServingStatus.MAINTENANCE

    if probe is ProbeKind.LIVENESS:
        # Process is alive if we reached the handler.
        return ServingStatus.SERVING

    if probe is ProbeKind.STARTUP:
        return ServingStatus.SERVING if startup_complete else ServingStatus.STARTING

    # READINESS:
    # - If startup not complete => NOT_SERVING
    if not startup_complete:
        return ServingStatus.NOT_SERVING

    # - If any critical dependency NOT_SERVING => NOT_SERVING
    # - If only non-critical failures => DEGRADED
    critical_bad = any(d.status is not ServingStatus.SERVING and d.attributes.get("critical", "true") == "true" for d in deps if d.attributes is not None)
    # attributes["critical"] filled below; but ensure backward-compat:
    critical_bad = any((d.status is not ServingStatus.SERVING) and d.name_attr_is_critical for d in _with_critical_flag(deps)) if deps else False
    noncritical_bad = any((d.status is not ServingStatus.SERVING) and not d.name_attr_is_critical for d in _with_critical_flag(deps)) if deps else False

    if critical_bad:
        return ServingStatus.NOT_SERVING
    if noncritical_bad:
        return ServingStatus.DEGRADED
    return ServingStatus.SERVING


def _with_critical_flag(deps: List[DependencyStatus]):
    # Helper to inject a dynamic property 'name_attr_is_critical' based on attributes["critical"]
    class _W:
        __slots__ = ("status", "attributes", "name_attr_is_critical")
        def __init__(self, d: DependencyStatus) -> None:
            self.status = d.status
            self.attributes = d.attributes or {}
            self.name_attr_is_critical = (self.attributes.get("critical", "true").lower() == "true")
    return [_W(d) for d in deps]


def _now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)


async def _collect_dependencies(request: Request, include: bool) -> List[DependencyStatus]:
    if not include:
        return []
    reg: Optional[HealthRegistry] = getattr(request.app.state, "health_registry", None)
    if not reg:
        return []
    checks = await asyncio.gather(*(_run_check(spec) for spec in reg.all().values()))
    # Annotate critical flag in attributes for aggregation
    for spec in reg.all().values():
        # find corresponding dep
        for d in checks:
            if d.name == spec.name:
                d.attributes = dict(d.attributes or {})
                d.attributes.setdefault("critical", "true" if spec.critical else "false")
    return checks


def _build_version_info() -> Tuple[str, str]:
    version = _env("APP_VERSION", "") or _env("IMAGE_TAG", "") or "unknown"
    revision = _env("GIT_SHA", "") or _env("SOURCE_REVISION", "") or _env("GITHUB_SHA", "") or "unknown"
    return version, revision


def _region() -> Optional[str]:
    return _env("REGION") or _env("CLOUD_REGION") or None


def _runtime_string() -> Optional[str]:
    try:
        import platform  # stdlib
        return f"{platform.python_implementation()} {platform.python_version()}"
    except Exception:  # noqa: BLE001
        return None


def _uptime_seconds() -> float:
    return time.monotonic() - START_TIME_MONO


def _process_metrics() -> Tuple[Optional[float], Optional[int]]:
    # cpu_utilization (0..1) and rss_bytes
    try:
        import psutil  # type: ignore
        p = psutil.Process()
        cpu = p.cpu_percent(interval=0.05) / 100.0  # short sampling
        rss = int(p.memory_info().rss)
        return cpu, rss
    except Exception:
        # Fallbacks without psutil
        cpu = None
        rss = None
        try:
            import resource  # type: ignore
            rss_pages = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            # ru_maxrss is KiB on Linux? Platform-dependent; treat as KiB if suspiciously small.
            rss = int(rss_pages) * 1024
        except Exception:
            pass
        return cpu, rss


# ==============
# Dependencies
# ==============

async def get_startup_complete(request: Request) -> bool:
    return bool(getattr(request.app.state, "startup_complete", True))

async def get_maintenance_mode(request: Request) -> bool:
    return bool(getattr(request.app.state, "maintenance_mode", False))


# ==========
# Endpoints
# ==========

@router.get("/healthz", response_model=HealthCheckResponse)
async def healthz(
    request: Request,
    include_dependencies: bool = False,
    wait_for_ready: bool = False,
    startup_complete: bool = Depends(get_startup_complete),
    maintenance_mode: bool = Depends(get_maintenance_mode),
) -> JSONResponse:
    """
    General health endpoint (defaults to READINESS semantics).
    """
    probe = ProbeKind.READINESS
    version, revision = _build_version_info()
    deps = await _collect_dependencies(request, include_dependencies)

    # Optionally wait for readiness (bounded)
    if wait_for_ready and not startup_complete:
        try:
            # Poll startup flag for up to 10 seconds
            await asyncio.wait_for(_wait_until(lambda: getattr(request.app.state, "startup_complete", False)), timeout=10.0)
            startup_complete = True
        except asyncio.TimeoutError:
            pass

    status = _aggregate_status(probe, deps, startup_complete, maintenance_mode)

    resp = HealthCheckResponse(
        status=status,
        service="policy-core",
        probe=probe,
        checked_at=_now_utc(),
        version=version,
        revision=revision,
        node=os.uname().nodename if hasattr(os, "uname") else None,
        region=_region(),
        dependencies=deps,
        diagnostics={
            "uptime_s": f"{_uptime_seconds():.2f}",
            "maintenance": str(maintenance_mode).lower(),
        },
        outages_total=int(getattr(request.app.state, "outages_total", 0)),
    )
    return JSONResponse(content=json.loads(resp.json()))


@router.get("/readyz", response_model=HealthCheckResponse)
async def readyz(
    request: Request,
    include_dependencies: bool = True,
    startup_complete: bool = Depends(get_startup_complete),
    maintenance_mode: bool = Depends(get_maintenance_mode),
) -> JSONResponse:
    """
    Readiness: requires critical dependencies SERVING and startup complete.
    """
    probe = ProbeKind.READINESS
    version, revision = _build_version_info()
    deps = await _collect_dependencies(request, include_dependencies)
    status = _aggregate_status(probe, deps, startup_complete, maintenance_mode)
    resp = HealthCheckResponse(
        status=status,
        service="policy-core",
        probe=probe,
        checked_at=_now_utc(),
        version=version,
        revision=revision,
        node=os.uname().nodename if hasattr(os, "uname") else None,
        region=_region(),
        dependencies=deps,
        diagnostics={"uptime_s": f"{_uptime_seconds():.2f}"},
        outages_total=int(getattr(request.app.state, "outages_total", 0)),
    )
    return JSONResponse(content=json.loads(resp.json()))


@router.get("/startupz", response_model=HealthCheckResponse)
async def startupz(
    request: Request,
    include_dependencies: bool = False,
    startup_complete: bool = Depends(get_startup_complete),
    maintenance_mode: bool = Depends(get_maintenance_mode),
) -> JSONResponse:
    """
    Startup probe: SERVING only after initialization/migrations.
    """
    probe = ProbeKind.STARTUP
    version, revision = _build_version_info()
    deps = await _collect_dependencies(request, include_dependencies)
    status = _aggregate_status(probe, deps, startup_complete, maintenance_mode)
    resp = HealthCheckResponse(
        status=status,
        service="policy-core",
        probe=probe,
        checked_at=_now_utc(),
        version=version,
        revision=revision,
        node=os.uname().nodename if hasattr(os, "uname") else None,
        region=_region(),
        dependencies=deps,
        diagnostics={"uptime_s": f"{_uptime_seconds():.2f}"},
        outages_total=int(getattr(request.app.state, "outages_total", 0)),
    )
    return JSONResponse(content=json.loads(resp.json()))


@router.get("/healthz/watch")
async def healthz_watch(
    request: Request,
    min_interval_ms: int = 2000,
    include_dependencies: bool = True,
    startup_complete: bool = Depends(get_startup_complete),
    maintenance_mode: bool = Depends(get_maintenance_mode),
) -> StreamingResponse:
    """
    SSE stream of readiness snapshots. Sends an immediate snapshot, then not more often than min_interval_ms.
    """

    async def event_gen():
        nonlocal startup_complete
        version, revision = _build_version_info()
        interval = max(200, min_interval_ms) / 1000.0  # clamp to [0.2s..]
        while True:
            if await _client_disconnected(request):
                break
            deps = await _collect_dependencies(request, include_dependencies)
            status = _aggregate_status(ProbeKind.READINESS, deps, startup_complete, maintenance_mode)
            snapshot = HealthCheckResponse(
                status=status,
                service="policy-core",
                probe=ProbeKind.READINESS,
                checked_at=_now_utc(),
                version=version,
                revision=revision,
                node=os.uname().nodename if hasattr(os, "uname") else None,
                region=_region(),
                dependencies=deps,
                diagnostics={"uptime_s": f"{_uptime_seconds():.2f}"},
                outages_total=int(getattr(request.app.state, "outages_total", 0)),
            )
            data = snapshot.json()
            yield f"data: {data}\n\n"
            try:
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                break

    return StreamingResponse(event_gen(), media_type="text/event-stream")


@router.get("/buildinfo", response_model=BuildInfo)
async def buildinfo() -> JSONResponse:
    version, revision = _build_version_info()
    build_time_env = _env("BUILD_TIME")
    build_dt: Optional[datetime] = None
    if build_time_env:
        try:
            build_dt = datetime.fromisoformat(build_time_env.replace("Z", "+00:00"))
        except Exception:
            build_dt = None

    info = BuildInfo(
        version=version,
        commit_sha=revision,
        vcs_url=_env("VCS_URL") or _env("GIT_URL"),
        build_time=build_dt,
        runtime=_runtime_string(),
        features=[f for f in (_env("FEATURE_FLAGS") or "").split(",") if f] or [],
        metadata={
            "image": _env("IMAGE_REF", "") or "",
            "region": _region() or "",
        },
    )
    return JSONResponse(content=json.loads(info.json()))


@router.get("/metrics/summary", response_model=MetricsSummary)
async def metrics_summary(request: Request) -> JSONResponse:
    cpu, rss = _process_metrics()
    # Optional simple RPS meter that app may expose (float seconds window, count)
    rps: float = 0.0
    try:
        meter = getattr(request.app.state, "request_meter", None)
        if meter and isinstance(meter, dict):
            # expected keys: window_s, count
            window = float(meter.get("window_s", 60.0)) or 60.0
            count = int(meter.get("count", 0))
            rps = count / window
    except Exception:
        rps = 0.0

    summary = MetricsSummary(
        uptime_seconds=_uptime_seconds(),
        cpu_utilization=cpu,
        rss_bytes=rss,
        rps=rps,
    )
    return JSONResponse(content=json.loads(summary.json()))


# ============================
# Helpers and wiring utilities
# ============================

async def _client_disconnected(request: Request) -> bool:
    # FastAPI provides client_disconnected flag on Request if server supports it
    try:
        return await request.is_disconnected()
    except Exception:
        return False


async def _wait_until(pred: Callable[[], bool], poll: float = 0.05) -> None:
    while not pred():
        await asyncio.sleep(poll)


# ===========
# Example wiring (optional, to be used from your app startup)
# ===========

async def _ping_tcp(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


def default_health_registry_from_env() -> HealthRegistry:
    """
    Example factory that registers a few common dependency checks.
    Critical flags and endpoints are set; replace with concrete async checks in your project.
    """
    specs: List[DependencySpec] = []

    # Postgres (critical)
    pg_dsn = _env("POSTGRES_DSN")
    if pg_dsn:
        async def pg_check() -> Tuple[ServingStatus, Optional[str], Dict[str, str]]:
            # Lightweight TCP check as placeholder; replace with real pool ping if available
            host, port = _parse_host_port_from_dsn(pg_dsn, default_port=5432)
            ok = await _ping_tcp(host, port, timeout=1.0)
            return (ServingStatus.SERVING if ok else ServingStatus.NOT_SERVING,
                    None if ok else "TCP connect failed",
                    {"driver": "postgres", "critical": "true"})
        specs.append(DependencySpec(name="postgres", fn=pg_check, critical=True, endpoint=pg_dsn, timeout_s=1.5))

    # Redis (non-critical example)
    redis_url = _env("REDIS_URL")
    if redis_url:
        async def redis_check() -> Tuple[ServingStatus, Optional[str], Dict[str, str]]:
            host, port = _parse_host_port_from_url(redis_url, default_port=6379)
            ok = await _ping_tcp(host, port, timeout=0.7)
            return (ServingStatus.SERVING if ok else ServingStatus.NOT_SERVING,
                    None if ok else "TCP connect failed",
                    {"driver": "redis", "critical": "false"})
        specs.append(DependencySpec(name="redis", fn=redis_check, critical=False, endpoint=redis_url, timeout_s=1.0))

    # OPA (critical)
    opa_url = _env("OPA_URL")
    if opa_url:
        async def opa_check() -> Tuple[ServingStatus, Optional[str], Dict[str, str]]:
            host, port = _parse_host_port_from_url(opa_url, default_port=8181)
            ok = await _ping_tcp(host, port, timeout=0.7)
            return (ServingStatus.SERVING if ok else ServingStatus.NOT_SERVING,
                    None if ok else "TCP connect failed",
                    {"driver": "opa", "critical": "true"})
        specs.append(DependencySpec(name="opa", fn=opa_check, critical=True, endpoint=opa_url, timeout_s=1.0))

    return HealthRegistry(specs)


def _parse_host_port_from_dsn(dsn: str, default_port: int) -> Tuple[str, int]:
    # naive parse for host:port from DSN; replace with robust parser in your project
    # Example DSN: postgresql://user:pass@host:5432/dbname
    try:
        return _parse_host_port_from_url(dsn, default_port=default_port)
    except Exception:
        return ("127.0.0.1", default_port)


def _parse_host_port_from_url(url: str, default_port: int) -> Tuple[str, int]:
    from urllib.parse import urlparse
    u = urlparse(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or default_port
    return host, int(port)
