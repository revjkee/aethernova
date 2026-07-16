# agent_mash/monitoring/inspection/detailed_inspector.py
from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
import json
import os
import platform
import re
import socket
import sys
import time
import traceback
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any, Optional

# Optional dependencies (best-effort)
try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None  # type: ignore


class InspectionError(Exception):
    pass


@dataclasses.dataclass(frozen=True)
class InspectorConfig:
    service: str = "agent_mash"
    mode: str = "deep"  # deep|fast
    total_timeout_s: float = 3.0
    per_section_timeout_s: float = 1.0
    max_env_items: int = 40
    max_open_files: int = 50
    max_threads: int = 200
    redact_patterns: tuple[str, ...] = (
        r"(?i)secret",
        r"(?i)password",
        r"(?i)token",
        r"(?i)api[_-]?key",
        r"(?i)private[_-]?key",
        r"(?i)access[_-]?key",
        r"(?i)session",
        r"(?i)cookie",
        r"(?i)auth",
        r"(?i)jwt",
        r"(?i)bearer",
    )


@dataclasses.dataclass(frozen=True)
class InspectionSection:
    name: str
    ok: bool
    latency_ms: int
    data: dict[str, Any]
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "name": self.name,
            "ok": self.ok,
            "latency_ms": self.latency_ms,
            "data": self.data,
        }
        if self.error:
            d["error"] = self.error
        return d


@dataclasses.dataclass(frozen=True)
class InspectionReport:
    service: str
    ts_unix: int
    ts_utc: str
    hostname: str
    pid: int
    mode: str
    ok: bool
    sections: tuple[InspectionSection, ...]
    summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "ts_unix": self.ts_unix,
            "ts_utc": self.ts_utc,
            "hostname": self.hostname,
            "pid": self.pid,
            "mode": self.mode,
            "ok": self.ok,
            "summary": self.summary,
            "sections": [s.to_dict() for s in self.sections],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"), sort_keys=False)


_SectionFn = Callable[[InspectorConfig], Awaitable[InspectionSection]]


class DetailedInspector:
    """
    Industrial diagnostic inspector.
    - Async, time-budgeted, parallel section execution
    - Secret-redaction of environment and free-form values
    - Works without psutil (degrades gracefully)
    - Intended for /debug/inspect endpoint or on-demand support snapshots
    """

    def __init__(self, *, config: Optional[InspectorConfig] = None) -> None:
        self._config = config or InspectorConfig()
        self._sections: dict[str, _SectionFn] = {}
        self._compiled_redactors = tuple(re.compile(p) for p in self._config.redact_patterns)

        # Built-in sections
        self.register("runtime", self._inspect_runtime)
        self.register("process", self._inspect_process)
        self.register("system", self._inspect_system)
        self.register("env", self._inspect_env)
        self.register("network", self._inspect_network)
        self.register("event_loop", self._inspect_event_loop)

    @property
    def config(self) -> InspectorConfig:
        return self._config

    def register(self, name: str, fn: _SectionFn) -> None:
        if not name or not isinstance(name, str):
            raise ValueError("section name must be non-empty string")
        if not callable(fn):
            raise ValueError("section fn must be callable")
        if name in self._sections:
            raise ValueError(f"section already registered: {name}")
        self._sections[name] = fn

    def unregister(self, name: str) -> None:
        self._sections.pop(name, None)

    def list_sections(self) -> tuple[str, ...]:
        return tuple(sorted(self._sections.keys()))

    async def inspect(self, *, override: Optional[InspectorConfig] = None) -> InspectionReport:
        cfg = override or self._config
        started = time.monotonic()
        hostname = _safe_hostname()
        pid = _safe_pid()
        ts_unix = int(time.time())
        ts_utc = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        async def run_one(name: str, fn: _SectionFn) -> InspectionSection:
            t0 = time.monotonic()
            try:
                sec = await asyncio.wait_for(fn(cfg), timeout=cfg.per_section_timeout_s)
                if sec.name != name:
                    sec = dataclasses.replace(sec, name=name)
                return sec
            except asyncio.TimeoutError:
                return InspectionSection(
                    name=name,
                    ok=False,
                    latency_ms=_ms(time.monotonic() - t0),
                    data={},
                    error=f"timeout>{cfg.per_section_timeout_s}s",
                )
            except Exception as e:
                return InspectionSection(
                    name=name,
                    ok=False,
                    latency_ms=_ms(time.monotonic() - t0),
                    data={},
                    error=_format_exc(e),
                )

        tasks = [asyncio.create_task(run_one(n, f)) for n, f in self._sections.items()]
        sections: list[InspectionSection] = []
        try:
            done, pending = await asyncio.wait(tasks, timeout=cfg.total_timeout_s)
            for d in done:
                try:
                    sections.append(d.result())
                except Exception as e:  # pragma: no cover
                    sections.append(
                        InspectionSection(
                            name="__internal__",
                            ok=False,
                            latency_ms=_ms(time.monotonic() - started),
                            data={},
                            error=_format_exc(e),
                        )
                    )
            if pending:
                for p in pending:
                    p.cancel()
                sections.append(
                    InspectionSection(
                        name="__budget__",
                        ok=False,
                        latency_ms=_ms(time.monotonic() - started),
                        data={"budget_s": cfg.total_timeout_s},
                        error="total timeout budget exceeded",
                    )
                )
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()

        sections_sorted = tuple(sorted(sections, key=lambda s: s.name))
        ok = all(s.ok for s in sections_sorted if not s.name.startswith("__"))

        summary = {
            "ok": ok,
            "latency_ms": _ms(time.monotonic() - started),
            "sections_ok": sum(1 for s in sections_sorted if s.ok),
            "sections_total": len(sections_sorted),
            "mode": cfg.mode,
        }

        return InspectionReport(
            service=str(cfg.service),
            ts_unix=ts_unix,
            ts_utc=ts_utc,
            hostname=hostname,
            pid=pid,
            mode=str(cfg.mode),
            ok=bool(ok),
            sections=sections_sorted,
            summary=summary,
        )

    # -------------------------
    # Built-in inspection logic
    # -------------------------

    async def _inspect_runtime(self, cfg: InspectorConfig) -> InspectionSection:
        t0 = time.monotonic()
        data = {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "executable": sys.executable,
            "platform": platform.platform(),
            "argv0": (sys.argv[0] if sys.argv else ""),
            "cwd": os.getcwd(),
        }
        return InspectionSection("runtime", True, _ms(time.monotonic() - t0), data)

    async def _inspect_process(self, cfg: InspectorConfig) -> InspectionSection:
        t0 = time.monotonic()
        data: dict[str, Any] = {"pid": _safe_pid()}

        if psutil is None:
            data["psutil"] = "unavailable"
            return InspectionSection("process", True, _ms(time.monotonic() - t0), data)

        ok = True
        try:
            p = psutil.Process(os.getpid())
            with p.oneshot():
                data["ppid"] = int(p.ppid())
                data["status"] = str(p.status())
                data["create_time_unix"] = float(p.create_time())
                data["cpu_num"] = int(p.cpu_num())
                data["num_threads"] = int(p.num_threads())
                mi = p.memory_info()
                data["rss_bytes"] = int(mi.rss)
                data["vms_bytes"] = int(mi.vms)

                # open files can be heavy; cap
                files = []
                try:
                    for of in p.open_files()[: int(max(0, cfg.max_open_files))]:
                        files.append({"path": str(getattr(of, "path", "")), "fd": int(getattr(of, "fd", -1))})
                except Exception as e:
                    files = [{"error": _format_exc(e)}]
                    ok = False
                data["open_files"] = files
        except Exception as e:
            ok = False
            data["error"] = _format_exc(e)

        # hard guardrail: thread explosion
        thr = data.get("num_threads")
        if isinstance(thr, int) and thr > int(cfg.max_threads):
            ok = False
            data["thread_guardrail"] = {"max_threads": int(cfg.max_threads), "observed": thr}

        return InspectionSection("process", ok, _ms(time.monotonic() - t0), data)

    async def _inspect_system(self, cfg: InspectorConfig) -> InspectionSection:
        t0 = time.monotonic()
        data: dict[str, Any] = {"hostname": _safe_hostname()}

        if psutil is None:
            data["psutil"] = "unavailable"
            return InspectionSection("system", True, _ms(time.monotonic() - t0), data)

        ok = True
        try:
            vm = psutil.virtual_memory()
            data["mem_total_bytes"] = int(vm.total)
            data["mem_available_bytes"] = int(vm.available)
            data["mem_percent"] = float(vm.percent)

            du = psutil.disk_usage(os.getcwd())
            data["disk_total_bytes"] = int(du.total)
            data["disk_free_bytes"] = int(du.free)
            data["disk_percent"] = float(du.percent)

            try:
                la = os.getloadavg()
                data["loadavg_1m"] = float(la[0])
                data["loadavg_5m"] = float(la[1])
                data["loadavg_15m"] = float(la[2])
            except Exception:
                data["loadavg"] = "unavailable"

            # simple guardrails
            if float(vm.percent) >= 95.0:
                ok = False
                data["guardrail_mem"] = {"threshold_percent": 95.0, "observed_percent": float(vm.percent)}
            if float(du.percent) >= 95.0:
                ok = False
                data["guardrail_disk"] = {"threshold_percent": 95.0, "observed_percent": float(du.percent)}
        except Exception as e:
            ok = False
            data["error"] = _format_exc(e)

        return InspectionSection("system", ok, _ms(time.monotonic() - t0), data)

    async def _inspect_env(self, cfg: InspectorConfig) -> InspectionSection:
        t0 = time.monotonic()
        ok = True

        # Do not dump everything; only safe subset + redaction.
        # Keep deterministic order.
        keys = sorted(os.environ.keys())
        items = []
        for k in keys[: int(max(0, cfg.max_env_items))]:
            v = os.environ.get(k, "")
            redacted = self._redact(k, v)
            items.append({"k": k, "v": redacted})
        data = {"items": items, "truncated": len(keys) > int(cfg.max_env_items), "total_keys": len(keys)}
        return InspectionSection("env", ok, _ms(time.monotonic() - t0), data)

    async def _inspect_network(self, cfg: InspectorConfig) -> InspectionSection:
        t0 = time.monotonic()
        ok = True
        data: dict[str, Any] = {}

        try:
            data["fqdn"] = socket.getfqdn()
        except Exception as e:
            ok = False
            data["fqdn_error"] = _format_exc(e)

        # DNS resolution check: local hostname
        try:
            hn = _safe_hostname()
            data["hostname"] = hn
            data["hostname_ips"] = _safe_getaddrinfo(hn)
        except Exception as e:
            ok = False
            data["dns_error"] = _format_exc(e)

        return InspectionSection("network", ok, _ms(time.monotonic() - t0), data)

    async def _inspect_event_loop(self, cfg: InspectorConfig) -> InspectionSection:
        t0 = time.monotonic()
        ok = True
        data: dict[str, Any] = {}

        try:
            loop = asyncio.get_running_loop()
            data["loop_class"] = loop.__class__.__name__
            data["debug"] = bool(loop.get_debug())
        except Exception:
            data["loop_class"] = "unknown"

        # loop lag probe
        before = time.monotonic()
        await asyncio.sleep(0)
        after = time.monotonic()
        lag_ms = _ms(after - before)
        data["loop_lag_ms"] = lag_ms

        # guardrails based on mode
        if str(cfg.mode).lower() == "fast":
            warn, fail = 250, 750
        else:
            warn, fail = 150, 500

        data["loop_lag_warn_ms"] = warn
        data["loop_lag_fail_ms"] = fail
        if lag_ms >= fail:
            ok = False
        elif lag_ms >= warn:
            ok = False  # conservative: inspector should flag degradation as not ok

        return InspectionSection("event_loop", ok, _ms(time.monotonic() - t0), data)

    # -------------------------
    # Redaction
    # -------------------------

    def _redact(self, key: str, value: str) -> str:
        k = str(key)
        v = "" if value is None else str(value)

        # If key matches sensitive patterns, fully redact.
        for rx in self._compiled_redactors:
            if rx.search(k):
                return "***REDACTED***"

        # If value looks like token (very long / high entropy-ish), partially redact.
        if len(v) >= 48 and re.search(r"[A-Za-z0-9_\-]{32,}", v):
            return v[:6] + "***REDACTED***" + v[-4:]

        return v


def _ms(seconds: float) -> int:
    if seconds <= 0:
        return 0
    return int(round(seconds * 1000.0))


def _safe_pid() -> int:
    try:
        return os.getpid()
    except Exception:
        return -1


def _safe_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"


def _safe_getaddrinfo(host: str) -> list[str]:
    out: list[str] = []
    try:
        infos = socket.getaddrinfo(host, None)
        for inf in infos:
            addr = inf[4][0]
            if addr not in out:
                out.append(addr)
    except Exception:
        return []
    return out


def _format_exc(e: BaseException) -> str:
    msg = f"{e.__class__.__name__}: {e}"
    try:
        tb = traceback.extract_tb(e.__traceback__)
        if tb:
            last = tb[-1]
            msg += f" @ {last.filename}:{last.lineno} in {last.name}"
    except Exception:
        pass
    return msg
