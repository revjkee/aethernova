# agent_mash/core/healthcheck.py
from __future__ import annotations

import asyncio
import dataclasses
import enum
import os
import platform
import socket
import time
import traceback
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Optional

# Optional deps (best-effort). Module remains fully functional without them.
try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None  # type: ignore

try:
    import sqlalchemy  # type: ignore
    from sqlalchemy.ext.asyncio import AsyncEngine  # type: ignore
except Exception:  # pragma: no cover
    sqlalchemy = None  # type: ignore
    AsyncEngine = Any  # type: ignore


class HealthState(str, enum.Enum):
    OK = "ok"
    DEGRADED = "degraded"
    FAIL = "fail"
    TIMEOUT = "timeout"
    SKIP = "skip"


@dataclasses.dataclass(frozen=True)
class HealthCheckResult:
    name: str
    state: HealthState
    latency_ms: int
    detail: dict[str, Any]
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "name": self.name,
            "state": self.state.value,
            "latency_ms": self.latency_ms,
            "detail": self.detail,
        }
        if self.error:
            d["error"] = self.error
        return d


@dataclasses.dataclass(frozen=True)
class HealthReport:
    service: str
    state: HealthState
    ts_unix: int
    uptime_s: int
    checks: tuple[HealthCheckResult, ...]
    meta: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "state": self.state.value,
            "ts_unix": self.ts_unix,
            "uptime_s": self.uptime_s,
            "meta": self.meta,
            "checks": [c.to_dict() for c in self.checks],
        }


_CheckFn = Callable[[], Awaitable[HealthCheckResult]]


class HealthCheckRegistry:
    """
    Industrial-grade async healthcheck registry with:
      - parallel execution
      - per-check timeout
      - global timeout budget
      - lightweight in-process cache (TTL)
      - deterministic aggregation (fail > timeout > degraded > ok)
    """

    __slots__ = (
        "_service",
        "_start_monotonic",
        "_checks",
        "_cache_ttl_s",
        "_cache_until",
        "_cache_value",
        "_lock",
    )

    def __init__(self, *, service: str, cache_ttl_s: float = 0.0) -> None:
        self._service = service
        self._start_monotonic = time.monotonic()
        self._checks: dict[str, _CheckFn] = {}
        self._cache_ttl_s = float(cache_ttl_s)
        self._cache_until = 0.0
        self._cache_value: Optional[HealthReport] = None
        self._lock = asyncio.Lock()

    @property
    def service(self) -> str:
        return self._service

    def register(self, name: str, fn: _CheckFn) -> None:
        if not name or not isinstance(name, str):
            raise ValueError("healthcheck name must be a non-empty string")
        if not callable(fn):
            raise ValueError("healthcheck fn must be callable")
        if name in self._checks:
            raise ValueError(f"healthcheck already registered: {name}")
        self._checks[name] = fn

    def unregister(self, name: str) -> None:
        self._checks.pop(name, None)

    def list_checks(self) -> tuple[str, ...]:
        return tuple(sorted(self._checks.keys()))

    async def run(
        self,
        *,
        per_check_timeout_s: float = 1.5,
        total_timeout_s: float = 3.0,
        include_meta: bool = True,
    ) -> HealthReport:
        now = time.monotonic()

        # Cache hot-path (safe for liveness/readiness endpoints).
        if self._cache_ttl_s > 0.0 and now < self._cache_until and self._cache_value is not None:
            return self._cache_value

        async with self._lock:
            now2 = time.monotonic()
            if self._cache_ttl_s > 0.0 and now2 < self._cache_until and self._cache_value is not None:
                return self._cache_value

            report = await self._run_uncached(
                per_check_timeout_s=per_check_timeout_s,
                total_timeout_s=total_timeout_s,
                include_meta=include_meta,
            )
            if self._cache_ttl_s > 0.0:
                self._cache_value = report
                self._cache_until = time.monotonic() + self._cache_ttl_s
            return report

    async def _run_uncached(
        self,
        *,
        per_check_timeout_s: float,
        total_timeout_s: float,
        include_meta: bool,
    ) -> HealthReport:
        checks = self._checks.copy()
        started = time.monotonic()

        async def run_one(name: str, fn: _CheckFn) -> HealthCheckResult:
            t0 = time.monotonic()
            try:
                res = await asyncio.wait_for(fn(), timeout=per_check_timeout_s)
                # Normalize: enforce name match, ensure required fields.
                if res.name != name:
                    res = dataclasses.replace(res, name=name)
                return res
            except asyncio.TimeoutError:
                return HealthCheckResult(
                    name=name,
                    state=HealthState.TIMEOUT,
                    latency_ms=_ms(time.monotonic() - t0),
                    detail={},
                    error=f"timeout>{per_check_timeout_s}s",
                )
            except Exception as e:
                return HealthCheckResult(
                    name=name,
                    state=HealthState.FAIL,
                    latency_ms=_ms(time.monotonic() - t0),
                    detail={},
                    error=_format_exc(e),
                )

        tasks = [asyncio.create_task(run_one(n, f)) for n, f in checks.items()]

        results: list[HealthCheckResult] = []
        try:
            done, pending = await asyncio.wait(tasks, timeout=total_timeout_s)
            for d in done:
                try:
                    results.append(d.result())
                except Exception as e:  # pragma: no cover
                    results.append(
                        HealthCheckResult(
                            name="__internal__",
                            state=HealthState.FAIL,
                            latency_ms=_ms(time.monotonic() - started),
                            detail={},
                            error=_format_exc(e),
                        )
                    )

            # Mark pending as TIMEOUT (global budget).
            if pending:
                for p in pending:
                    p.cancel()
                for _ in pending:
                    results.append(
                        HealthCheckResult(
                            name="__budget__",
                            state=HealthState.TIMEOUT,
                            latency_ms=_ms(time.monotonic() - started),
                            detail={"budget_s": total_timeout_s},
                            error="total timeout budget exceeded",
                        )
                    )
        finally:
            # Ensure no orphan tasks
            for t in tasks:
                if not t.done():
                    t.cancel()

        # Deterministic ordering
        results_sorted = tuple(sorted(results, key=lambda r: r.name))

        overall = _aggregate_state(results_sorted)

        meta = self._build_meta() if include_meta else {}
        uptime_s = int(time.monotonic() - self._start_monotonic)
        ts_unix = int(time.time())
        return HealthReport(
            service=self._service,
            state=overall,
            ts_unix=ts_unix,
            uptime_s=uptime_s,
            checks=results_sorted,
            meta=meta,
        )


def _aggregate_state(checks: tuple[HealthCheckResult, ...]) -> HealthState:
    # Priority: FAIL > TIMEOUT > DEGRADED > OK > SKIP
    worst = HealthState.OK
    for c in checks:
        if c.state == HealthState.FAIL:
            return HealthState.FAIL
        if c.state == HealthState.TIMEOUT:
            worst = HealthState.TIMEOUT
        elif c.state == HealthState.DEGRADED and worst not in (HealthState.TIMEOUT, HealthState.FAIL):
            worst = HealthState.DEGRADED
        elif c.state == HealthState.SKIP and worst == HealthState.OK:
            worst = HealthState.SKIP
    return worst


def _ms(seconds: float) -> int:
    # Safe rounding with clamp
    if seconds <= 0:
        return 0
    return int(round(seconds * 1000.0))


def _format_exc(e: BaseException) -> str:
    # Compact but debuggable; includes exception class and message.
    msg = f"{e.__class__.__name__}: {e}"
    # Add last frame info (without huge trace) for production triage.
    try:
        tb = traceback.extract_tb(e.__traceback__)
        if tb:
            last = tb[-1]
            msg += f" @ {last.filename}:{last.lineno} in {last.name}"
    except Exception:  # pragma: no cover
        pass
    return msg


def _safe_getenv(name: str, default: str = "") -> str:
    try:
        return os.getenv(name, default)
    except Exception:  # pragma: no cover
        return default


def _hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:  # pragma: no cover
        return "unknown"


def _pid() -> int:
    try:
        return os.getpid()
    except Exception:  # pragma: no cover
        return -1


def _python_meta() -> dict[str, Any]:
    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
    }


def _process_meta() -> dict[str, Any]:
    d: dict[str, Any] = {"pid": _pid()}
    if psutil is None:
        d["psutil"] = "unavailable"
        return d
    try:
        p = psutil.Process(os.getpid())
        with p.oneshot():
            d["rss_bytes"] = int(p.memory_info().rss)
            d["cpu_num"] = int(p.cpu_num())
            d["threads"] = int(p.num_threads())
            d["open_files"] = int(len(p.open_files()))
    except Exception as e:
        d["psutil_error"] = _format_exc(e)
    return d


def _system_meta() -> dict[str, Any]:
    d: dict[str, Any] = {"host": _hostname()}
    if psutil is None:
        d["system"] = "psutil_unavailable"
        return d
    try:
        vm = psutil.virtual_memory()
        d["mem_total_bytes"] = int(vm.total)
        d["mem_available_bytes"] = int(vm.available)
        d["mem_percent"] = float(vm.percent)
        if hasattr(psutil, "getloadavg"):
            la = os.getloadavg()
            d["loadavg_1m"] = float(la[0])
            d["loadavg_5m"] = float(la[1])
            d["loadavg_15m"] = float(la[2])
    except Exception as e:
        d["system_error"] = _format_exc(e)
    return d


def _runtime_env_meta() -> dict[str, Any]:
    # Only safe, non-secret hints; never dump full env.
    return {
        "env": _safe_getenv("ENV", _safe_getenv("APP_ENV", "")),
        "service": _safe_getenv("SERVICE_NAME", ""),
        "version": _safe_getenv("SERVICE_VERSION", _safe_getenv("GIT_SHA", "")),
        "region": _safe_getenv("REGION", ""),
    }


def _event_loop_meta() -> dict[str, Any]:
    d: dict[str, Any] = {}
    try:
        loop = asyncio.get_running_loop()
        d["loop"] = loop.__class__.__name__
        d["debug"] = bool(loop.get_debug())
    except Exception:
        d["loop"] = "unknown"
    return d


def _merge_meta(*maps: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for m in maps:
        for k, v in m.items():
            if v is None:
                continue
            out[k] = v
    return out


def default_registry(*, service: str, cache_ttl_s: float = 0.0) -> HealthCheckRegistry:
    """
    Factory for a registry with sensible built-in checks.
    You can register additional checks from other modules.
    """
    reg = HealthCheckRegistry(service=service, cache_ttl_s=cache_ttl_s)

    reg.register("event_loop_lag", make_event_loop_lag_check(warn_ms=150, fail_ms=500))
    reg.register("disk_space", make_disk_space_check(path=".", min_free_bytes=256 * 1024 * 1024))
    reg.register("process", make_process_check())
    reg.register("system", make_system_check())

    return reg


def make_event_loop_lag_check(*, warn_ms: int = 150, fail_ms: int = 500) -> _CheckFn:
    async def _check() -> HealthCheckResult:
        name = "event_loop_lag"
        t0 = time.monotonic()
        # Measure loop scheduling delay.
        before = time.monotonic()
        await asyncio.sleep(0)
        after = time.monotonic()
        lag_ms = _ms(after - before)

        state = HealthState.OK
        if lag_ms >= fail_ms:
            state = HealthState.FAIL
        elif lag_ms >= warn_ms:
            state = HealthState.DEGRADED

        return HealthCheckResult(
            name=name,
            state=state,
            latency_ms=_ms(time.monotonic() - t0),
            detail={"lag_ms": lag_ms, "warn_ms": warn_ms, "fail_ms": fail_ms},
        )

    return _check


def make_disk_space_check(*, path: str = ".", min_free_bytes: int = 256 * 1024 * 1024) -> _CheckFn:
    async def _check() -> HealthCheckResult:
        name = "disk_space"
        t0 = time.monotonic()
        try:
            st = os.statvfs(path)
            free = int(st.f_bavail) * int(st.f_frsize)
            total = int(st.f_blocks) * int(st.f_frsize)
            used = max(total - free, 0)
            pct_used = float(used) / float(total) * 100.0 if total > 0 else 0.0

            state = HealthState.OK
            if free < int(min_free_bytes):
                state = HealthState.DEGRADED

            return HealthCheckResult(
                name=name,
                state=state,
                latency_ms=_ms(time.monotonic() - t0),
                detail={
                    "path": os.path.abspath(path),
                    "free_bytes": free,
                    "total_bytes": total,
                    "used_percent": round(pct_used, 2),
                    "min_free_bytes": int(min_free_bytes),
                },
            )
        except Exception as e:
            return HealthCheckResult(
                name=name,
                state=HealthState.FAIL,
                latency_ms=_ms(time.monotonic() - t0),
                detail={"path": os.path.abspath(path)},
                error=_format_exc(e),
            )

    return _check


def make_process_check() -> _CheckFn:
    async def _check() -> HealthCheckResult:
        name = "process"
        t0 = time.monotonic()
        detail: dict[str, Any] = {}
        try:
            detail.update(_process_meta())
            state = HealthState.OK
            if detail.get("pid", -1) <= 0:
                state = HealthState.DEGRADED
            return HealthCheckResult(
                name=name,
                state=state,
                latency_ms=_ms(time.monotonic() - t0),
                detail=detail,
            )
        except Exception as e:
            return HealthCheckResult(
                name=name,
                state=HealthState.FAIL,
                latency_ms=_ms(time.monotonic() - t0),
                detail=detail,
                error=_format_exc(e),
            )

    return _check


def make_system_check() -> _CheckFn:
    async def _check() -> HealthCheckResult:
        name = "system"
        t0 = time.monotonic()
        detail: dict[str, Any] = {}
        try:
            detail.update(_system_meta())
            # If psutil is missing, don't fail health entirely: mark as SKIP.
            if psutil is None:
                return HealthCheckResult(
                    name=name,
                    state=HealthState.SKIP,
                    latency_ms=_ms(time.monotonic() - t0),
                    detail=detail,
                )
            state = HealthState.OK
            mem_percent = detail.get("mem_percent")
            if isinstance(mem_percent, (int, float)) and mem_percent >= 92.0:
                state = HealthState.DEGRADED
            return HealthCheckResult(
                name=name,
                state=state,
                latency_ms=_ms(time.monotonic() - t0),
                detail=detail,
            )
        except Exception as e:
            return HealthCheckResult(
                name=name,
                state=HealthState.FAIL,
                latency_ms=_ms(time.monotonic() - t0),
                detail=detail,
                error=_format_exc(e),
            )

    return _check


def make_tcp_connect_check(*, host: str, port: int, name: Optional[str] = None) -> _CheckFn:
    check_name = name or f"tcp:{host}:{port}"

    async def _check() -> HealthCheckResult:
        t0 = time.monotonic()
        try:
            reader, writer = await asyncio.open_connection(host=host, port=int(port))
            try:
                return HealthCheckResult(
                    name=check_name,
                    state=HealthState.OK,
                    latency_ms=_ms(time.monotonic() - t0),
                    detail={"host": host, "port": int(port)},
                )
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
        except Exception as e:
            return HealthCheckResult(
                name=check_name,
                state=HealthState.FAIL,
                latency_ms=_ms(time.monotonic() - t0),
                detail={"host": host, "port": int(port)},
                error=_format_exc(e),
            )

    return _check


def make_http_get_check(
    *,
    url: str,
    name: Optional[str] = None,
    expected_status: int = 200,
    headers: Optional[Mapping[str, str]] = None,
) -> _CheckFn:
    """
    Best-effort HTTP check. Uses stdlib only (no requests/aiohttp dependency).
    For HTTPS, relies on urllib which is blocking; runs in a thread to keep loop healthy.
    """
    import urllib.request

    check_name = name or f"http:{url}"

    def _blocking() -> tuple[int, int]:
        req = urllib.request.Request(url, headers=dict(headers or {}), method="GET")
        with urllib.request.urlopen(req, timeout=2.0) as resp:  # nosec B310 (healthcheck URL is controlled)
            status = int(getattr(resp, "status", 0) or 0)
            length = int(resp.headers.get("Content-Length") or 0)
            return status, length

    async def _check() -> HealthCheckResult:
        t0 = time.monotonic()
        try:
            status, length = await asyncio.to_thread(_blocking)
            state = HealthState.OK if status == int(expected_status) else HealthState.DEGRADED
            return HealthCheckResult(
                name=check_name,
                state=state,
                latency_ms=_ms(time.monotonic() - t0),
                detail={"url": url, "status": status, "expected_status": int(expected_status), "content_length": length},
            )
        except Exception as e:
            return HealthCheckResult(
                name=check_name,
                state=HealthState.FAIL,
                latency_ms=_ms(time.monotonic() - t0),
                detail={"url": url, "expected_status": int(expected_status)},
                error=_format_exc(e),
            )

    return _check


def make_sqlalchemy_async_check(*, engine: Any, name: str = "db") -> _CheckFn:
    """
    SQLAlchemy AsyncEngine check (SELECT 1).
    - If SQLAlchemy is not installed, returns SKIP.
    - Engine type is Any to avoid hard dependency.
    """
    async def _check() -> HealthCheckResult:
        t0 = time.monotonic()
        if sqlalchemy is None:
            return HealthCheckResult(
                name=name,
                state=HealthState.SKIP,
                latency_ms=_ms(time.monotonic() - t0),
                detail={"reason": "sqlalchemy_unavailable"},
            )
        try:
            # Validate minimally without importing project internals.
            async with engine.connect() as conn:  # type: ignore[union-attr]
                await conn.execute(sqlalchemy.text("SELECT 1"))  # type: ignore[attr-defined]
            return HealthCheckResult(
                name=name,
                state=HealthState.OK,
                latency_ms=_ms(time.monotonic() - t0),
                detail={"driver": "sqlalchemy_async", "query": "SELECT 1"},
            )
        except Exception as e:
            return HealthCheckResult(
                name=name,
                state=HealthState.FAIL,
                latency_ms=_ms(time.monotonic() - t0),
                detail={"driver": "sqlalchemy_async"},
                error=_format_exc(e),
            )

    return _check


def build_health_report_meta() -> dict[str, Any]:
    return _merge_meta(_runtime_env_meta(), _python_meta(), _event_loop_meta(), {"host": _hostname(), "pid": _pid()})


# Injected into registry report; separated for testability/immutability.
def _build_static_meta() -> dict[str, Any]:
    return _merge_meta(build_health_report_meta())


def _is_probably_container() -> bool:
    # Heuristic only; safe to omit if uncertain.
    # We do not claim "container" as fact; we emit a best-effort signal.
    try:
        if os.path.exists("/.dockerenv"):
            return True
        cgroup = "/proc/1/cgroup"
        if os.path.exists(cgroup):
            with open(cgroup, "r", encoding="utf-8", errors="ignore") as f:
                data = f.read()
            if "docker" in data or "kubepods" in data or "containerd" in data:
                return True
    except Exception:
        return False
    return False


def _best_effort_deploy_meta() -> dict[str, Any]:
    return {
        "container_signal": bool(_is_probably_container()),
        "k8s_pod": _safe_getenv("HOSTNAME", ""),
        "node": _safe_getenv("K8S_NODE_NAME", ""),
    }


def _now_iso_utc() -> str:
    # Avoid external deps; basic ISO string.
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _meta_snapshot() -> dict[str, Any]:
    return _merge_meta(
        _build_static_meta(),
        _best_effort_deploy_meta(),
        {"ts_utc": _now_iso_utc()},
    )


def _clamp_int(x: Any, default: int = 0) -> int:
    try:
        v = int(x)
        return v
    except Exception:
        return int(default)


def _clamp_float(x: Any, default: float = 0.0) -> float:
    try:
        v = float(x)
        return v
    except Exception:
        return float(default)


def _non_empty_str(x: Any, default: str = "") -> str:
    try:
        s = str(x)
        return s if s else default
    except Exception:
        return default


def _sanitize_meta(meta: dict[str, Any]) -> dict[str, Any]:
    # Ensure JSON-serializable, avoid leaking secrets by design.
    out: dict[str, Any] = {}
    for k, v in meta.items():
        if v is None:
            continue
        if isinstance(v, (str, int, float, bool)):
            out[_non_empty_str(k, "k")] = v
            continue
        # Reduce complex types
        out[_non_empty_str(k, "k")] = _non_empty_str(v, "")
    return out


def _report_meta_final() -> dict[str, Any]:
    return _sanitize_meta(_meta_snapshot())


def _registry_meta_override(reg: HealthCheckRegistry) -> dict[str, Any]:
    # Internal extension point: allow consistent meta in all reports.
    return _report_meta_final()


# Attach meta builder to registry without subclassing.
def _patch_registry_meta(reg: HealthCheckRegistry) -> None:
    def _build_meta_bound() -> dict[str, Any]:
        return _registry_meta_override(reg)

    # Bind as method-like attribute.
    setattr(reg, "_build_meta", _build_meta_bound)


# Ensure meta method exists even if registry is used directly.
def ensure_registry_is_patched(reg: HealthCheckRegistry) -> HealthCheckRegistry:
    if not hasattr(reg, "_build_meta"):
        _patch_registry_meta(reg)
    return reg
