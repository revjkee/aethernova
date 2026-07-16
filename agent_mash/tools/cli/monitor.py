# agent_mash/tools/cli/monitor.py
# -*- coding: utf-8 -*-
"""
Production-grade CLI monitor for agent_mash.

Features
- Subcommands: system, process, http
- Async sampling loop with graceful shutdown
- Output formats: text, json (NDJSON)
- Thresholds (warn/crit) with deterministic exit codes
- No mandatory third-party deps (psutil is optional)

Exit codes
0  OK (no crit conditions)
1  WARN (warn triggered, no crit)
2  CRIT (crit triggered)
3  INVALID / runtime error
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import dataclasses
import json
import logging
import os
import platform
import shutil
import signal
import socket
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


LOG = logging.getLogger("agent_mash.monitor")


# ----------------------------
# Optional psutil integration
# ----------------------------
try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None  # type: ignore


# ----------------------------
# Utilities
# ----------------------------
def _now_unix() -> float:
    return time.time()


def _iso_utc(ts: Optional[float] = None) -> str:
    if ts is None:
        ts = _now_unix()
    # Avoid datetime import overhead; keep stable ISO-like string.
    # We still want UTC: use time.gmtime.
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _clamp_nonneg(x: float) -> float:
    return x if x >= 0 else 0.0


def _human_bytes(num: float) -> str:
    # Stable, compact human format.
    step = 1024.0
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(num) < step:
            return f"{num:,.1f} {unit}"
        num /= step
    return f"{num:,.1f} EiB"


def _safe_div(n: float, d: float) -> float:
    if d == 0:
        return 0.0
    return n / d


def _is_tty() -> bool:
    with contextlib.suppress(Exception):
        return sys.stdout.isatty()
    return False


def _term_width(default: int = 100) -> int:
    with contextlib.suppress(Exception):
        return shutil.get_terminal_size((default, 20)).columns
    return default


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=False)


def _validate_positive_float(name: str, v: float) -> float:
    if v <= 0:
        raise ValueError(f"{name} must be > 0")
    return v


def _validate_nonneg_float(name: str, v: float) -> float:
    if v < 0:
        raise ValueError(f"{name} must be >= 0")
    return v


# ----------------------------
# Threshold evaluation
# ----------------------------
@dataclass(frozen=True)
class Thresholds:
    warn: Optional[float] = None
    crit: Optional[float] = None

    def evaluate(self, value: Optional[float]) -> int:
        """
        Returns severity:
        0 OK, 1 WARN, 2 CRIT
        If value is None -> OK (not measurable).
        """
        if value is None:
            return 0
        if self.crit is not None and value >= self.crit:
            return 2
        if self.warn is not None and value >= self.warn:
            return 1
        return 0


def _merge_severity(a: int, b: int) -> int:
    return a if a >= b else b


# ----------------------------
# Result models
# ----------------------------
@dataclass
class Sample:
    ts: float
    kind: str
    data: Dict[str, Any]
    severity: int = 0
    notes: Optional[str] = None


# ----------------------------
# System metrics
# ----------------------------
def _system_cpu_percent(interval_sec: float) -> Optional[float]:
    if psutil is not None:
        # psutil.cpu_percent blocks for interval if interval > 0
        return float(psutil.cpu_percent(interval=interval_sec))
    # Fallback: approximate using os.getloadavg if available (not percent)
    return None


def _system_mem() -> Dict[str, Any]:
    if psutil is not None:
        vm = psutil.virtual_memory()
        return {
            "total": int(vm.total),
            "available": int(vm.available),
            "used": int(vm.used),
            "free": int(getattr(vm, "free", 0)),
            "percent": float(vm.percent),
        }

    # Fallback: not reliable cross-platform without external deps.
    return {"total": None, "available": None, "used": None, "free": None, "percent": None}


def _system_disk(path: str) -> Dict[str, Any]:
    try:
        usage = shutil.disk_usage(path)
        used = usage.used
        total = usage.total
        free = usage.free
        percent = float(_safe_div(used * 100.0, total))
        return {
            "path": path,
            "total": int(total),
            "used": int(used),
            "free": int(free),
            "percent": percent,
        }
    except Exception as e:
        return {"path": path, "error": str(e), "total": None, "used": None, "free": None, "percent": None}


def _system_loadavg() -> Dict[str, Any]:
    if hasattr(os, "getloadavg"):
        try:
            la = os.getloadavg()
            return {"1m": float(la[0]), "5m": float(la[1]), "15m": float(la[2])}
        except Exception as e:
            return {"error": str(e), "1m": None, "5m": None, "15m": None}
    return {"1m": None, "5m": None, "15m": None}


def collect_system_sample(
    *,
    cpu_threshold: Thresholds,
    mem_threshold: Thresholds,
    disk_threshold: Thresholds,
    disk_path: str,
    cpu_sample_interval: float,
) -> Sample:
    ts = _now_unix()

    cpu_percent = _system_cpu_percent(cpu_sample_interval)
    mem = _system_mem()
    disk = _system_disk(disk_path)
    loadavg = _system_loadavg()

    sev = 0
    sev = _merge_severity(sev, cpu_threshold.evaluate(cpu_percent))
    sev = _merge_severity(sev, mem_threshold.evaluate(mem.get("percent")))
    sev = _merge_severity(sev, disk_threshold.evaluate(disk.get("percent")))

    return Sample(
        ts=ts,
        kind="system",
        data={
            "host": socket.gethostname(),
            "platform": platform.platform(),
            "python": sys.version.split()[0],
            "cpu_percent": cpu_percent,
            "mem": mem,
            "disk": disk,
            "loadavg": loadavg,
        },
        severity=sev,
    )


# ----------------------------
# Process metrics
# ----------------------------
def _process_sample_psutil(pid: int) -> Dict[str, Any]:
    p = psutil.Process(pid)  # type: ignore[union-attr]
    with p.oneshot():
        create_time = float(p.create_time())
        status = str(p.status())
        name = str(p.name())
        exe = None
        with contextlib.suppress(Exception):
            exe = p.exe()
        cmdline = None
        with contextlib.suppress(Exception):
            cmdline = p.cmdline()
        cpu = float(p.cpu_percent(interval=None))  # last interval since last call
        mem_info = p.memory_info()
        rss = int(mem_info.rss)
        vms = int(getattr(mem_info, "vms", 0))
        threads = int(p.num_threads())
        username = None
        with contextlib.suppress(Exception):
            username = p.username()

    return {
        "pid": pid,
        "name": name,
        "status": status,
        "create_time": create_time,
        "uptime_sec": _clamp_nonneg(_now_unix() - create_time),
        "exe": exe,
        "cmdline": cmdline,
        "cpu_percent": cpu,
        "mem_rss": rss,
        "mem_vms": vms,
        "threads": threads,
        "username": username,
    }


def _process_sample_fallback(pid: int) -> Dict[str, Any]:
    # Minimal fallback: verifies existence and returns what we can.
    # Windows and non-/proc systems: extremely limited without psutil.
    exists = True
    with contextlib.suppress(Exception):
        os.kill(pid, 0)
    # If os.kill raises on Windows for permission reasons, we still treat as exists.
    return {
        "pid": pid,
        "exists": exists,
        "cpu_percent": None,
        "mem_rss": None,
        "mem_vms": None,
        "threads": None,
        "uptime_sec": None,
        "name": None,
        "status": None,
        "exe": None,
        "cmdline": None,
        "username": None,
    }


def collect_process_sample(
    *,
    pid: int,
    cpu_threshold: Thresholds,
    rss_threshold_bytes: Thresholds,
) -> Sample:
    ts = _now_unix()
    if pid <= 0:
        return Sample(ts=ts, kind="process", data={"pid": pid, "error": "invalid pid"}, severity=2)

    try:
        if psutil is not None:
            data = _process_sample_psutil(pid)
        else:
            data = _process_sample_fallback(pid)
    except Exception as e:
        return Sample(ts=ts, kind="process", data={"pid": pid, "error": str(e)}, severity=2)

    sev = 0
    sev = _merge_severity(sev, cpu_threshold.evaluate(data.get("cpu_percent")))
    rss = data.get("mem_rss")
    rss_mb = None
    if isinstance(rss, (int, float)):
        rss_mb = float(rss)
    sev = _merge_severity(sev, rss_threshold_bytes.evaluate(rss_mb))

    return Sample(ts=ts, kind="process", data=data, severity=sev)


# ----------------------------
# HTTP metrics
# ----------------------------
def _http_request(url: str, timeout_sec: float, method: str = "GET") -> Tuple[Optional[int], Optional[float], Optional[str]]:
    start = _now_unix()
    req = urllib.request.Request(url=url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            code = int(getattr(resp, "status", 200))
            _ = resp.read(256)  # bounded read to avoid large payloads
        latency = _clamp_nonneg(_now_unix() - start)
        return code, latency, None
    except urllib.error.HTTPError as e:
        latency = _clamp_nonneg(_now_unix() - start)
        return int(getattr(e, "code", 0)), latency, f"HTTPError: {e}"
    except Exception as e:
        latency = _clamp_nonneg(_now_unix() - start)
        return None, latency, str(e)


def collect_http_sample(
    *,
    url: str,
    timeout_sec: float,
    latency_threshold: Thresholds,
    status_crit_from: int,
) -> Sample:
    ts = _now_unix()
    code, latency, err = _http_request(url=url, timeout_sec=timeout_sec)

    sev = 0
    sev = _merge_severity(sev, latency_threshold.evaluate(latency))
    if code is None:
        sev = _merge_severity(sev, 2)
    elif code >= status_crit_from:
        sev = _merge_severity(sev, 2)

    return Sample(
        ts=ts,
        kind="http",
        data={
            "url": url,
            "timeout_sec": timeout_sec,
            "status_code": code,
            "latency_sec": latency,
            "error": err,
        },
        severity=sev,
    )


# ----------------------------
# Rendering
# ----------------------------
SEV_LABEL = {0: "OK", 1: "WARN", 2: "CRIT"}


def render_text(sample: Sample) -> str:
    w = _term_width(110)
    head = f"{_iso_utc(sample.ts)} {sample.kind.upper()} {SEV_LABEL.get(sample.severity, 'UNK')}"
    line = "-" * min(w, 110)

    if sample.kind == "system":
        cpu = sample.data.get("cpu_percent")
        mem = sample.data.get("mem", {}) or {}
        disk = sample.data.get("disk", {}) or {}
        la = sample.data.get("loadavg", {}) or {}

        cpu_s = "n/a" if cpu is None else f"{float(cpu):.1f}%"
        mem_p = mem.get("percent")
        mem_s = "n/a" if mem_p is None else f"{float(mem_p):.1f}%"
        disk_p = disk.get("percent")
        disk_s = "n/a" if disk_p is None else f"{float(disk_p):.1f}%"
        la_s = f"{la.get('1m')},{la.get('5m')},{la.get('15m')}"

        total = mem.get("total")
        avail = mem.get("available")
        total_s = "n/a" if total is None else _human_bytes(float(total))
        avail_s = "n/a" if avail is None else _human_bytes(float(avail))

        disk_total = disk.get("total")
        disk_free = disk.get("free")
        disk_total_s = "n/a" if disk_total is None else _human_bytes(float(disk_total))
        disk_free_s = "n/a" if disk_free is None else _human_bytes(float(disk_free))

        body = [
            f"host={sample.data.get('host')} platform={sample.data.get('platform')}",
            f"cpu={cpu_s} mem={mem_s} (avail={avail_s} total={total_s})",
            f"disk={disk_s} (free={disk_free_s} total={disk_total_s}) path={disk.get('path')}",
            f"loadavg={la_s}",
        ]
        return "\n".join([head, line, *body])

    if sample.kind == "process":
        d = sample.data
        if "error" in d:
            return "\n".join([head, line, f"pid={d.get('pid')} error={d.get('error')}"])
        cpu = d.get("cpu_percent")
        rss = d.get("mem_rss")
        vms = d.get("mem_vms")
        cpu_s = "n/a" if cpu is None else f"{float(cpu):.1f}%"
        rss_s = "n/a" if rss is None else _human_bytes(float(rss))
        vms_s = "n/a" if vms is None else _human_bytes(float(vms))
        up = d.get("uptime_sec")
        up_s = "n/a" if up is None else f"{float(up):.0f}s"
        return "\n".join(
            [
                head,
                line,
                f"pid={d.get('pid')} name={d.get('name')} status={d.get('status')} user={d.get('username')}",
                f"cpu={cpu_s} rss={rss_s} vms={vms_s} threads={d.get('threads')} uptime={up_s}",
                f"exe={d.get('exe')}",
                f"cmdline={d.get('cmdline')}",
            ]
        )

    if sample.kind == "http":
        d = sample.data
        code = d.get("status_code")
        lat = d.get("latency_sec")
        code_s = "n/a" if code is None else str(code)
        lat_s = "n/a" if lat is None else f"{float(lat):.3f}s"
        err = d.get("error")
        body = [f"url={d.get('url')}", f"status={code_s} latency={lat_s} timeout={d.get('timeout_sec')}"]
        if err:
            body.append(f"error={err}")
        return "\n".join([head, line, *body])

    return "\n".join([head, line, _json_dumps(sample.data)])


def render_json(sample: Sample) -> str:
    obj = {
        "ts": sample.ts,
        "ts_iso": _iso_utc(sample.ts),
        "kind": sample.kind,
        "severity": sample.severity,
        "severity_label": SEV_LABEL.get(sample.severity, "UNK"),
        "data": sample.data,
    }
    if sample.notes:
        obj["notes"] = sample.notes
    return _json_dumps(obj)


# ----------------------------
# Runtime loop
# ----------------------------
@dataclass
class RunConfig:
    interval_sec: float
    count: int
    output: str  # text|json
    quiet: bool


class GracefulStop:
    def __init__(self) -> None:
        self._event = asyncio.Event()

    def request(self) -> None:
        self._event.set()

    async def wait(self) -> None:
        await self._event.wait()

    def is_requested(self) -> bool:
        return self._event.is_set()


def _setup_logging(quiet: bool) -> None:
    level = logging.WARNING if quiet else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


def _install_signal_handlers(stop: GracefulStop) -> None:
    def _handler(signum: int, _frame: Any) -> None:
        LOG.info("stop requested by signal=%s", signum)
        stop.request()

    with contextlib.suppress(Exception):
        signal.signal(signal.SIGINT, _handler)
    with contextlib.suppress(Exception):
        signal.signal(signal.SIGTERM, _handler)


def _print_line(s: str) -> None:
    sys.stdout.write(s + ("\n" if not s.endswith("\n") else ""))
    sys.stdout.flush()


def _emit(sample: Sample, fmt: str) -> None:
    if fmt == "json":
        _print_line(render_json(sample))
    else:
        _print_line(render_text(sample))


def _final_exit_code(max_sev: int) -> int:
    if max_sev <= 0:
        return 0
    if max_sev == 1:
        return 1
    if max_sev >= 2:
        return 2
    return 3


async def run_loop(
    *,
    stop: GracefulStop,
    run_cfg: RunConfig,
    sampler,
) -> int:
    max_sev = 0
    interval = _validate_positive_float("interval_sec", run_cfg.interval_sec)
    count = run_cfg.count
    if count == 0:
        # 0 means infinite in this CLI
        remaining = None
    else:
        if count < 0:
            raise ValueError("count must be >= 0")
        remaining = count

    next_tick = _now_unix()

    while True:
        if stop.is_requested():
            break
        if remaining is not None and remaining <= 0:
            break

        # sleep until next scheduled tick
        now = _now_unix()
        delay = next_tick - now
        if delay > 0:
            try:
                await asyncio.wait_for(stop.wait(), timeout=delay)
                break
            except asyncio.TimeoutError:
                pass

        # sample
        try:
            sample: Sample = await sampler()
        except Exception as e:
            # Runtime sampler error -> CRIT and abort.
            err_sample = Sample(ts=_now_unix(), kind="runtime", data={"error": str(e)}, severity=2)
            _emit(err_sample, run_cfg.output)
            return 3

        max_sev = _merge_severity(max_sev, sample.severity)
        _emit(sample, run_cfg.output)

        if remaining is not None:
            remaining -= 1

        next_tick += interval

    return _final_exit_code(max_sev)


# ----------------------------
# CLI parsing
# ----------------------------
def _add_common_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--interval", type=float, default=2.0, help="Sampling interval seconds (default: 2.0)")
    p.add_argument("--count", type=int, default=0, help="Number of samples; 0 means infinite (default: 0)")
    p.add_argument("--output", choices=("text", "json"), default="text", help="Output format (default: text)")
    p.add_argument("--quiet", action="store_true", help="Less logs")


def _add_threshold_args(
    p: argparse.ArgumentParser,
    *,
    prefix: str,
    help_unit: str,
) -> None:
    p.add_argument(f"--{prefix}-warn", type=float, default=None, help=f"Warn threshold ({help_unit})")
    p.add_argument(f"--{prefix}-crit", type=float, default=None, help=f"Crit threshold ({help_unit})")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-mash-monitor",
        description="Industrial CLI monitor (system/process/http).",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # system
    p_sys = sub.add_parser("system", help="Monitor system metrics")
    _add_common_args(p_sys)
    _add_threshold_args(p_sys, prefix="cpu", help_unit="percent")
    _add_threshold_args(p_sys, prefix="mem", help_unit="percent")
    _add_threshold_args(p_sys, prefix="disk", help_unit="percent")
    p_sys.add_argument("--disk-path", type=str, default=".", help="Disk path for usage (default: .)")
    p_sys.add_argument(
        "--cpu-sample",
        type=float,
        default=0.2,
        help="CPU percent sampling window in seconds (psutil only; default: 0.2)",
    )

    # process
    p_proc = sub.add_parser("process", help="Monitor a process by PID")
    _add_common_args(p_proc)
    p_proc.add_argument("--pid", type=int, required=True, help="Process PID")
    _add_threshold_args(p_proc, prefix="cpu", help_unit="percent")
    # RSS thresholds in MiB for CLI, internally converted to bytes
    p_proc.add_argument("--rss-warn-mib", type=float, default=None, help="Warn RSS threshold (MiB)")
    p_proc.add_argument("--rss-crit-mib", type=float, default=None, help="Crit RSS threshold (MiB)")

    # http
    p_http = sub.add_parser("http", help="Monitor an HTTP endpoint")
    _add_common_args(p_http)
    p_http.add_argument("--url", type=str, required=True, help="URL to probe")
    p_http.add_argument("--timeout", type=float, default=2.0, help="Request timeout seconds (default: 2.0)")
    _add_threshold_args(p_http, prefix="latency", help_unit="seconds")
    p_http.add_argument(
        "--status-crit-from",
        type=int,
        default=500,
        help="HTTP status >= this value triggers CRIT (default: 500)",
    )

    return parser


def _thresholds_from_args(warn: Optional[float], crit: Optional[float]) -> Thresholds:
    if warn is not None:
        _validate_nonneg_float("warn", warn)
    if crit is not None:
        _validate_nonneg_float("crit", crit)
    if warn is not None and crit is not None and crit < warn:
        raise ValueError("crit must be >= warn")
    return Thresholds(warn=warn, crit=crit)


def _mib_to_bytes(v: Optional[float]) -> Optional[float]:
    if v is None:
        return None
    _validate_nonneg_float("mib", v)
    return float(v) * 1024.0 * 1024.0


# ----------------------------
# Main entry
# ----------------------------
def main(argv: Optional[list[str]] = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(bool(getattr(args, "quiet", False)))

    stop = GracefulStop()
    _install_signal_handlers(stop)

    run_cfg = RunConfig(
        interval_sec=float(args.interval),
        count=int(args.count),
        output=str(args.output),
        quiet=bool(args.quiet),
    )

    async def _sampler_system():
        cpu_thr = _thresholds_from_args(getattr(args, "cpu_warn", None), getattr(args, "cpu_crit", None))
        mem_thr = _thresholds_from_args(getattr(args, "mem_warn", None), getattr(args, "mem_crit", None))
        disk_thr = _thresholds_from_args(getattr(args, "disk_warn", None), getattr(args, "disk_crit", None))
        disk_path = str(getattr(args, "disk_path", "."))
        cpu_sample = float(getattr(args, "cpu_sample", 0.2))
        if psutil is None:
            # If psutil missing, cpu_percent is None; still functional for mem/disk via fallbacks.
            cpu_sample = 0.0
        return collect_system_sample(
            cpu_threshold=cpu_thr,
            mem_threshold=mem_thr,
            disk_threshold=disk_thr,
            disk_path=disk_path,
            cpu_sample_interval=cpu_sample,
        )

    async def _sampler_process():
        cpu_thr = _thresholds_from_args(getattr(args, "cpu_warn", None), getattr(args, "cpu_crit", None))
        rss_warn_b = _mib_to_bytes(getattr(args, "rss_warn_mib", None))
        rss_crit_b = _mib_to_bytes(getattr(args, "rss_crit_mib", None))
        rss_thr = _thresholds_from_args(rss_warn_b, rss_crit_b)
        pid = int(getattr(args, "pid"))
        # For psutil cpu_percent to be meaningful, we need a priming call then wait at least one tick.
        if psutil is not None:
            with contextlib.suppress(Exception):
                _ = psutil.Process(pid).cpu_percent(interval=None)  # type: ignore[union-attr]
        return collect_process_sample(pid=pid, cpu_threshold=cpu_thr, rss_threshold_bytes=rss_thr)

    async def _sampler_http():
        latency_thr = _thresholds_from_args(getattr(args, "latency_warn", None), getattr(args, "latency_crit", None))
        url = str(getattr(args, "url"))
        timeout = float(getattr(args, "timeout"))
        status_crit_from = int(getattr(args, "status_crit_from"))
        _validate_positive_float("timeout", timeout)
        if status_crit_from < 100 or status_crit_from > 999:
            raise ValueError("status-crit-from must be a valid HTTP status boundary (100..999)")
        return collect_http_sample(
            url=url,
            timeout_sec=timeout,
            latency_threshold=latency_thr,
            status_crit_from=status_crit_from,
        )

    try:
        if args.cmd == "system":
            sampler = _sampler_system
        elif args.cmd == "process":
            sampler = _sampler_process
        elif args.cmd == "http":
            sampler = _sampler_http
        else:
            return 3

        # If output is text and stdout is not a TTY, keep output still readable and deterministic.
        # No extra behavior required; render_text is already stable.

        return asyncio.run(run_loop(stop=stop, run_cfg=run_cfg, sampler=sampler))
    except (ValueError, argparse.ArgumentError) as e:
        _print_line(_json_dumps({"ts_iso": _iso_utc(), "kind": "invalid", "error": str(e)}))
        return 3
    except KeyboardInterrupt:
        return 2
    except Exception as e:
        _print_line(_json_dumps({"ts_iso": _iso_utc(), "kind": "fatal", "error": str(e)}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
