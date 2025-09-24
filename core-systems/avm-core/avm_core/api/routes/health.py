# path: core-systems/avm_core/engine/api/routes/health.py
# -*- coding: utf-8 -*-
"""
Industrial-grade health endpoints for AVM engine.

Features:
- Endpoints: /livez, /readyz, /healthz (detailed), /startupz (+ HEAD handlers).
- Parallelized checks with per-check timeouts and severities (critical/warn/info).
- No external deps: stdlib only. Works in containers and bare metal.
- Safe JSON logs (no secrets), short TTL cache to reduce overhead.
- Environment flags to tune strictness:
    AVM_HEALTH_STRICT=1   -> readiness fails on any warning
    AVM_RUNTIME_DIR=/var/run/avm
    AVM_HEALTH_MIN_FREE_MB=100
    AVM_CHECK_VPN=1       -> check presence of wg/openvpn binaries
- Attempts to softly integrate with optional subsystems if available:
    avm_core.engine.scheduler, avm_core.engine.storage, avm_core.vpn.vpn_manager
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import platform
import shutil
import socket
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from fastapi import APIRouter, Response, status
from pydantic import BaseModel, Field

START_MONO = time.monotonic()
START_TS = int(time.time())

router = APIRouter(tags=["health"])

# -----------------------------
# Models
# -----------------------------

class Severity(str):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class CheckResult(BaseModel):
    name: str
    ok: bool
    severity: str = Field(default=Severity.INFO)
    time_ms: int
    error: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class HealthReport(BaseModel):
    service: str = "avm-engine"
    version: str = Field(default_factory=lambda: _detect_version())
    status: str
    liveness_ok: bool
    readiness_ok: bool
    uptime_s: int
    checks: List[CheckResult]
    summary: Dict[str, int]
    node: Dict[str, Any]


# -----------------------------
# Utilities
# -----------------------------

def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.lower() in ("1", "true", "yes", "on")

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, "").strip() or default)
    except Exception:
        return default

def _detect_version() -> str:
    # Prefer VERSION file near repo root, fallback to package version
    candidates = [
        Path(__file__).resolve().parents[4] / "VERSION",  # core-systems/avm-core/VERSION
        Path(__file__).resolve().parents[2] / "VERSION",  # fallback up the tree
    ]
    for p in candidates:
        with contextlib.suppress(Exception):
            if p.is_file():
                v = p.read_text(encoding="utf-8").strip()
                if v:
                    return v
    # Fallback to installed distribution version if present
    with contextlib.suppress(Exception):
        import importlib.metadata as im
        return im.version("avm-core")
    return "0.0.0+unknown"

def _hostname() -> str:
    with contextlib.suppress(Exception):
        return socket.gethostname()
    return "unknown-host"

def _short_json(obj: Any) -> str:
    with contextlib.suppress(Exception):
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return str(obj)

# TTL cache for health report to lower overhead under frequent probes
@dataclass
class _Cache:
    ts: float = 0.0
    data: Optional[HealthReport] = None
    ttl_s: float = 1.0  # small TTL keeps endpoints cheap under load

_CACHE = _Cache()

# -----------------------------
# Check runners
# -----------------------------

CheckCallable = Callable[[], Awaitable[CheckResult]]

async def _run_check(name: str,
                     fn: Callable[[], Awaitable[Tuple[bool, Dict[str, Any]]]],
                     severity: str,
                     timeout_s: float = 2.5) -> CheckResult:
    t0 = time.perf_counter()
    try:
        ok, details = await asyncio.wait_for(fn(), timeout=timeout_s)
        return CheckResult(name=name, ok=ok, severity=severity,
                           time_ms=int((time.perf_counter() - t0) * 1000), details=details)
    except asyncio.TimeoutError as e:
        return CheckResult(name=name, ok=False, severity=severity,
                           time_ms=int((time.perf_counter() - t0) * 1000),
                           error=f"timeout>{timeout_s}s")
    except Exception as e:
        return CheckResult(name=name, ok=False, severity=severity,
                           time_ms=int((time.perf_counter() - t0) * 1000),
                           error=str(e)[:500])

# -----------------------------
# Concrete checks
# -----------------------------

async def _check_event_loop() -> Tuple[bool, Dict[str, Any]]:
    # Schedule a noop and measure delay
    t0 = time.perf_counter()
    await asyncio.sleep(0)
    delay_ms = (time.perf_counter() - t0) * 1000.0
    # 50ms is conservative envelope for healthy loop under normal load
    ok = delay_ms < 50.0
    return ok, {"delay_ms": round(delay_ms, 3)}

async def _check_disk_space() -> Tuple[bool, Dict[str, Any]]:
    runtime_dir = Path(os.getenv("AVM_RUNTIME_DIR", "/tmp/avm-runtime"))
    runtime_dir.mkdir(parents=True, exist_ok=True)
    total, used, free = shutil.disk_usage(runtime_dir)
    min_free_mb = _env_int("AVM_HEALTH_MIN_FREE_MB", 100)
    ok = (free // (1024 * 1024)) >= min_free_mb
    return ok, {
        "path": str(runtime_dir),
        "free_mb": int(free / (1024 * 1024)),
        "min_free_mb": min_free_mb,
    }

async def _check_write_permissions() -> Tuple[bool, Dict[str, Any]]:
    runtime_dir = Path(os.getenv("AVM_RUNTIME_DIR", "/tmp/avm-runtime"))
    p = runtime_dir / f".rw_probe_{int(time.time()*1000)}"
    try:
        p.write_text("ok", encoding="utf-8")
        p.unlink(missing_ok=True)
        return True, {"path": str(runtime_dir)}
    except Exception as e:
        return False, {"path": str(runtime_dir), "error": str(e)[:300]}

async def _check_binaries() -> Tuple[bool, Dict[str, Any]]:
    # Check essential toolchain presence
    bins = {
        "qemu-system-x86_64": shutil.which("qemu-system-x86_64"),
        "qemu-img": shutil.which("qemu-img"),
    }
    # Optional VPN toolchain if requested
    if _env_bool("AVM_CHECK_VPN", False):
        bins.update({
            "wg": shutil.which("wg"),
            "wg-quick": shutil.which("wg-quick"),
            "openvpn": shutil.which("openvpn"),
        })
    ok = all(v is not None for v in bins.values())
    return ok, {k: ("ok" if v else "missing") for k, v in bins.items()}

async def _check_scheduler() -> Tuple[bool, Dict[str, Any]]:
    # Soft dependency: succeeds as "info" if module absent
    with contextlib.suppress(Exception):
        from avm_core.engine.scheduler import get_scheduler  # type: ignore
        sch = get_scheduler()  # expected to return singleton or raise
        active = getattr(sch, "active_jobs", lambda: [])()
        return True, {"active_jobs": len(active)}
    return True, {"skipped": "scheduler_not_present"}

async def _check_storage() -> Tuple[bool, Dict[str, Any]]:
    with contextlib.suppress(Exception):
        from avm_core.engine.storage import get_storage  # type: ignore
        st = get_storage()
        # Probe a cheap capability/API
        caps = getattr(st, "capabilities", lambda: {"probe":"ok"})()
        return True, {"capabilities": caps}
    return True, {"skipped": "storage_not_present"}

async def _check_vpn_manager() -> Tuple[bool, Dict[str, Any]]:
    with contextlib.suppress(Exception):
        from avm_core.vpn.vpn_manager import health_snapshot  # type: ignore
        snap = await health_snapshot() if asyncio.iscoroutinefunction(health_snapshot) else health_snapshot()
        # Expect {'tunnels': [...], 'healthy': bool}
        ok = bool(snap.get("healthy", True))
        return ok, {"tunnels": len(snap.get("tunnels", []))}
    # If VPN not wired in this build, don't fail readiness
    return True, {"skipped": "vpn_manager_not_present"}

# -----------------------------
# Aggregation
# -----------------------------

def _strict_mode() -> bool:
    return _env_bool("AVM_HEALTH_STRICT", False)

async def _collect_checks() -> List[CheckResult]:
    checks: List[Tuple[str, Callable[[], Awaitable[Tuple[bool, Dict[str, Any]]]], str, float]] = [
        ("event_loop", _check_event_loop,       Severity.CRITICAL, 2.0),
        ("disk_space", _check_disk_space,       Severity.CRITICAL, 2.0),
        ("write_perm", _check_write_permissions,Severity.CRITICAL, 2.0),
        ("binaries",   _check_binaries,         Severity.WARNING,  2.0),
        ("scheduler",  _check_scheduler,        Severity.INFO,     1.5),
        ("storage",    _check_storage,          Severity.INFO,     1.5),
        ("vpn",        _check_vpn_manager,      Severity.WARNING,  2.0),
    ]
    tasks = [ _run_check(n, f, sev, t) for (n, f, sev, t) in checks ]
    return await asyncio.gather(*tasks)

def _summarize(checks: List[CheckResult]) -> Dict[str, int]:
    total = len(checks)
    ok = sum(1 for c in checks if c.ok)
    bad = total - ok
    crit_bad = sum(1 for c in checks if not c.ok and c.severity == Severity.CRITICAL)
    warn_bad = sum(1 for c in checks if not c.ok and c.severity == Severity.WARNING)
    return {"total": total, "ok": ok, "bad": bad, "crit_bad": crit_bad, "warn_bad": warn_bad}

def _compute_readiness(checks: List[CheckResult]) -> bool:
    # Fail on any critical failure. In strict mode also fail on warnings.
    if any((not c.ok) and c.severity == Severity.CRITICAL for c in checks):
        return False
    if _strict_mode() and any((not c.ok) and c.severity == Severity.WARNING for c in checks):
        return False
    return True

def _node_info() -> Dict[str, Any]:
    return {
        "hostname": _hostname(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "pid": os.getpid(),
        "start_ts": START_TS,
    }

async def _build_report() -> HealthReport:
    checks = await _collect_checks()
    summary = _summarize(checks)
    liveness_ok = True  # process and loop made it here
    readiness_ok = _compute_readiness(checks)
    status_text = "ok" if (liveness_ok and readiness_ok) else "degraded"
    return HealthReport(
        status=status_text,
        liveness_ok=liveness_ok,
        readiness_ok=readiness_ok,
        uptime_s=int(time.monotonic() - START_MONO),
        checks=checks,
        summary=summary,
        node=_node_info(),
    )

async def _cached_report() -> HealthReport:
    now = time.monotonic()
    if _CACHE.data and (now - _CACHE.ts) < _CACHE.ttl_s:
        return _CACHE.data
    rep = await _build_report()
    _CACHE.data = rep
    _CACHE.ts = now
    return rep

# -----------------------------
# Endpoints
# -----------------------------

@router.get("/healthz", response_model=HealthReport, status_code=status.HTTP_200_OK)
async def healthz() -> HealthReport:
    """
    Detailed health report (expensive, but cached ~1s).
    Use in dashboards and manual probes.
    """
    return await _cached_report()

@router.get("/readyz")
async def readyz(response: Response) -> Dict[str, Any]:
    """
    Kubernetes Readiness. Fails on critical checks (and warnings if strict).
    """
    rep = await _cached_report()
    if not rep.readiness_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ready" if rep.readiness_ok else "not_ready",
        "summary": rep.summary,
        "strict": _strict_mode(),
    }

@router.get("/livez")
async def livez(response: Response) -> Dict[str, Any]:
    """
    Kubernetes Liveness. Very cheap: if we run and event loop responds – it's OK.
    """
    # Quick loop probe
    t0 = time.perf_counter()
    await asyncio.sleep(0)
    delay_ms = (time.perf_counter() - t0) * 1000.0
    ok = delay_ms < 250.0  # generous bound for liveness
    if not ok:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return {"status": "alive" if ok else "stalled", "delay_ms": round(delay_ms, 3)}

@router.get("/startupz")
async def startupz() -> Dict[str, Any]:
    """
    Kubernetes Startup probe. Consider healthy after small grace period.
    """
    grace = _env_int("AVM_STARTUP_GRACE_S", 5)
    ready = (time.monotonic() - START_MONO) >= grace
    return {"status": "started" if ready else "starting", "grace_s": grace, "uptime_s": int(time.monotonic() - START_MONO)}

# Cheap HEAD handlers for kubelet/ingress that do HEAD probes
@router.head("/livez")
async def livez_head(response: Response) -> Response:
    res = await livez(response)  # reuse logic; body will be dropped for HEAD
    return response

@router.head("/readyz")
async def readyz_head(response: Response) -> Response:
    res = await readyz(response)
    return response

@router.head("/startupz")
async def startupz_head() -> Response:
    return Response(status_code=status.HTTP_200_OK)
