# agent_mash/monitoring/diagnostics/quick_check.py
from __future__ import annotations

import argparse
import asyncio
import dataclasses
import datetime as dt
import json
import os
import platform
import socket
import ssl
import sys
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    ok: bool
    severity: str  # "info" | "warn" | "critical"
    message: str
    details: Mapping[str, Any] = field(default_factory=dict)
    duration_ms: int = 0


@dataclass(frozen=True, slots=True)
class RunSummary:
    ok: bool
    critical_failures: int
    warnings: int
    infos: int
    total_checks: int
    duration_ms: int


@dataclass(frozen=True, slots=True)
class RunReport:
    run_id: str
    started_at: str
    finished_at: str
    duration_ms: int
    host: Mapping[str, Any]
    python: Mapping[str, Any]
    config: Mapping[str, Any]
    results: List[CheckResult]
    summary: RunSummary


class ExitCode:
    OK = 0
    WARN = 10
    CRITICAL = 20
    INTERNAL_ERROR = 30


def _utcnow_iso() -> str:
    return dt.datetime.now(tz=dt.timezone.utc).isoformat()


def _ms(delta_s: float) -> int:
    if delta_s <= 0:
        return 0
    return int(delta_s * 1000)


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    v = v.strip().lower()
    return v in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    return _safe_int(v, default=default) if v is not None else default


def _env_str(name: str, default: str = "") -> str:
    v = os.getenv(name)
    return v if v is not None else default


def _truncate(s: str, n: int = 400) -> str:
    if len(s) <= n:
        return s
    return s[: n - 3] + "..."


async def _run_check(name: str, coro, *, severity: str) -> CheckResult:
    t0 = time.monotonic()
    try:
        msg, details = await coro
        ok = True
        return CheckResult(
            name=name,
            ok=ok,
            severity=severity,
            message=str(msg),
            details=dict(details or {}),
            duration_ms=_ms(time.monotonic() - t0),
        )
    except asyncio.CancelledError:
        raise
    except Exception as e:
        tb = traceback.format_exc()
        return CheckResult(
            name=name,
            ok=False,
            severity=severity,
            message=_truncate(f"{type(e).__name__}: {e}", 300),
            details={"traceback": _truncate(tb, 4000)},
            duration_ms=_ms(time.monotonic() - t0),
        )


def _host_info() -> Dict[str, Any]:
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "pid": os.getpid(),
        "cwd": os.getcwd(),
        "uid": getattr(os, "getuid", lambda: None)(),
        "gid": getattr(os, "getgid", lambda: None)(),
    }


def _python_info() -> Dict[str, Any]:
    return {
        "executable": sys.executable,
        "version": sys.version,
        "version_info": list(sys.version_info),
        "implementation": platform.python_implementation(),
    }


async def _check_env(required: Sequence[str]) -> Tuple[str, Dict[str, Any]]:
    missing: List[str] = []
    present: Dict[str, str] = {}
    for k in required:
        v = os.getenv(k)
        if v is None or v == "":
            missing.append(k)
        else:
            present[k] = "[set]"
    if missing:
        return ("Missing required environment variables", {"missing": missing, "present": present})
    return ("Environment variables OK", {"present": present})


async def _check_clock() -> Tuple[str, Dict[str, Any]]:
    now_utc = dt.datetime.now(tz=dt.timezone.utc)
    if now_utc.tzinfo is None:
        raise RuntimeError("UTC datetime is not timezone-aware")
    return ("Clock OK", {"utc_now": now_utc.isoformat()})


async def _check_filesystem(paths: Sequence[str]) -> Tuple[str, Dict[str, Any]]:
    checked: List[Dict[str, Any]] = []
    problems: List[Dict[str, Any]] = []

    for p in paths:
        ap = os.path.abspath(p)
        item: Dict[str, Any] = {"path": ap}
        exists = os.path.exists(ap)
        item["exists"] = exists
        if not exists:
            problems.append({"path": ap, "reason": "not_exists"})
            checked.append(item)
            continue

        item["is_dir"] = os.path.isdir(ap)
        item["is_file"] = os.path.isfile(ap)
        item["readable"] = os.access(ap, os.R_OK)
        item["writable"] = os.access(ap, os.W_OK)
        item["executable"] = os.access(ap, os.X_OK)
        try:
            st = os.stat(ap)
            item["mode"] = oct(st.st_mode)
            item["size"] = st.st_size
            item["mtime"] = dt.datetime.fromtimestamp(st.st_mtime, tz=dt.timezone.utc).isoformat()
        except Exception as e:
            problems.append({"path": ap, "reason": f"stat_error:{type(e).__name__}:{e}"})
        checked.append(item)

    if problems:
        return ("Filesystem issues detected", {"checked": checked, "problems": problems})
    return ("Filesystem OK", {"checked": checked})


async def _check_imports(mods: Sequence[str]) -> Tuple[str, Dict[str, Any]]:
    ok: List[str] = []
    fail: Dict[str, str] = {}
    for m in mods:
        try:
            __import__(m)
            ok.append(m)
        except Exception as e:
            fail[m] = _truncate(f"{type(e).__name__}: {e}", 300)
    if fail:
        return ("Import failures detected", {"ok": ok, "fail": fail})
    return ("Imports OK", {"ok": ok})


async def _check_asyncio() -> Tuple[str, Dict[str, Any]]:
    # Verifies basic scheduling, cancellation, and timeout behavior
    t0 = time.monotonic()

    async def _tiny():
        await asyncio.sleep(0)
        return "ok"

    r = await asyncio.wait_for(_tiny(), timeout=0.5)
    dt_s = time.monotonic() - t0
    if r != "ok":
        raise RuntimeError("Unexpected asyncio result")
    return ("Asyncio OK", {"roundtrip_ms": _ms(dt_s)})


async def _check_dns(hosts: Sequence[str], *, timeout_s: float) -> Tuple[str, Dict[str, Any]]:
    loop = asyncio.get_running_loop()
    resolved: Dict[str, Any] = {}
    failures: Dict[str, str] = {}

    async def _resolve(h: str) -> None:
        try:
            infos = await asyncio.wait_for(loop.getaddrinfo(h, None, proto=socket.IPPROTO_TCP), timeout=timeout_s)
            ips = []
            for info in infos:
                sockaddr = info[4]
                if sockaddr and isinstance(sockaddr, tuple) and len(sockaddr) >= 1:
                    ips.append(sockaddr[0])
            resolved[h] = sorted(set(ips))[:20]
        except Exception as e:
            failures[h] = _truncate(f"{type(e).__name__}: {e}", 300)

    await asyncio.gather(*[_resolve(h) for h in hosts], return_exceptions=False)

    if failures:
        return ("DNS resolution issues detected", {"resolved": resolved, "failures": failures})
    return ("DNS OK", {"resolved": resolved})


async def _check_tcp_endpoints(endpoints: Sequence[str], *, timeout_s: float) -> Tuple[str, Dict[str, Any]]:
    ok: Dict[str, Any] = {}
    fail: Dict[str, str] = {}

    async def _dial(endpoint: str) -> None:
        if ":" not in endpoint:
            fail[endpoint] = "invalid_format_expected_host:port"
            return
        host, port_s = endpoint.rsplit(":", 1)
        port = _safe_int(port_s, default=-1)
        if port <= 0 or port > 65535:
            fail[endpoint] = "invalid_port"
            return
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host=host, port=port), timeout=timeout_s)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            ok[endpoint] = "connected"
        except Exception as e:
            fail[endpoint] = _truncate(f"{type(e).__name__}: {e}", 300)

    import contextlib
    await asyncio.gather(*[_dial(ep) for ep in endpoints], return_exceptions=False)

    if fail:
        return ("TCP connectivity issues detected", {"ok": ok, "fail": fail})
    return ("TCP OK", {"ok": ok})


async def _check_https(urls: Sequence[str], *, timeout_s: float) -> Tuple[str, Dict[str, Any]]:
    ok: Dict[str, Any] = {}
    fail: Dict[str, str] = {}

    async def _probe(u: str) -> None:
        # Minimal HTTPS probe without external deps:
        # - parses https://host[:port]/path
        # - opens TLS socket
        # - sends HEAD
        if not u.startswith("https://"):
            fail[u] = "only_https_supported"
            return

        rest = u[len("https://") :]
        hostport, _, path = rest.partition("/")
        host, port = hostport, 443
        if ":" in hostport:
            host, port_s = hostport.rsplit(":", 1)
            port = _safe_int(port_s, default=443)
        path = "/" + path if path else "/"

        ctx = ssl.create_default_context()

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host=host, port=port, ssl=ctx, server_hostname=host),
                timeout=timeout_s,
            )
            req = f"HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: agent_mash_quick_check\r\n\r\n"
            writer.write(req.encode("utf-8", errors="ignore"))
            await asyncio.wait_for(writer.drain(), timeout=timeout_s)
            line = await asyncio.wait_for(reader.readline(), timeout=timeout_s)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

            line_s = line.decode("utf-8", errors="ignore").strip()
            ok[u] = {"status_line": _truncate(line_s, 200)}
        except Exception as e:
            fail[u] = _truncate(f"{type(e).__name__}: {e}", 300)

    import contextlib
    await asyncio.gather(*[_probe(u) for u in urls], return_exceptions=False)

    if fail:
        return ("HTTPS probe issues detected", {"ok": ok, "fail": fail})
    return ("HTTPS OK", {"ok": ok})


async def _check_psutil_optional() -> Tuple[str, Dict[str, Any]]:
    try:
        import psutil  # type: ignore
    except Exception as e:
        return ("psutil not available (optional)", {"available": False, "reason": _truncate(f"{type(e).__name__}: {e}", 240)})

    vm = psutil.virtual_memory()
    du = psutil.disk_usage(os.getcwd())
    cpu = psutil.cpu_percent(interval=0.1)
    return (
        "psutil OK",
        {
            "available": True,
            "cpu_percent": cpu,
            "mem_total": int(vm.total),
            "mem_available": int(vm.available),
            "mem_percent": float(vm.percent),
            "disk_total": int(du.total),
            "disk_free": int(du.free),
            "disk_percent": float(du.percent),
        },
    )


def _summarize(results: Sequence[CheckResult], total_ms: int) -> RunSummary:
    crit = sum(1 for r in results if (not r.ok and r.severity == "critical"))
    warn = sum(1 for r in results if (not r.ok and r.severity == "warn"))
    info = sum(1 for r in results if (not r.ok and r.severity == "info"))
    ok = (crit == 0)
    return RunSummary(
        ok=ok,
        critical_failures=crit,
        warnings=warn,
        infos=info,
        total_checks=len(results),
        duration_ms=total_ms,
    )


def _exit_code(summary: RunSummary) -> int:
    if summary.critical_failures > 0:
        return ExitCode.CRITICAL
    if summary.warnings > 0:
        return ExitCode.WARN
    return ExitCode.OK


async def run_quick_check(config: Mapping[str, Any]) -> RunReport:
    started_at = _utcnow_iso()
    run_id = config.get("run_id") or f"qc_{int(time.time())}_{os.getpid()}"
    t0 = time.monotonic()

    required_env = list(config.get("required_env", []))
    fs_paths = list(config.get("fs_paths", []))
    import_mods = list(config.get("import_modules", []))

    dns_hosts = list(config.get("dns_hosts", []))
    tcp_endpoints = list(config.get("tcp_endpoints", []))
    https_urls = list(config.get("https_urls", []))

    timeout_s = float(config.get("timeout_s", 2.0))
    concurrency = int(config.get("concurrency", 8))
    include_psutil = bool(config.get("include_psutil", True))

    sem = asyncio.Semaphore(max(1, concurrency))
    results: List[CheckResult] = []

    async def _guarded(name: str, coro, severity: str) -> None:
        async with sem:
            results.append(await _run_check(name, coro, severity=severity))

    tasks: List[asyncio.Task[None]] = []

    tasks.append(asyncio.create_task(_guarded("env.required", _check_env(required_env), "warn")))
    tasks.append(asyncio.create_task(_guarded("clock.utc", _check_clock(), "critical")))

    if fs_paths:
        tasks.append(asyncio.create_task(_guarded("fs.paths", _check_filesystem(fs_paths), "critical")))
    if import_mods:
        tasks.append(asyncio.create_task(_guarded("imports", _check_imports(import_mods), "critical")))

    tasks.append(asyncio.create_task(_guarded("asyncio.runtime", _check_asyncio(), "critical")))

    if dns_hosts:
        tasks.append(asyncio.create_task(_guarded("net.dns", _check_dns(dns_hosts, timeout_s=timeout_s), "warn")))
    if tcp_endpoints:
        tasks.append(asyncio.create_task(_guarded("net.tcp", _check_tcp_endpoints(tcp_endpoints, timeout_s=timeout_s), "warn")))
    if https_urls:
        tasks.append(asyncio.create_task(_guarded("net.https", _check_https(https_urls, timeout_s=timeout_s), "warn")))

    if include_psutil:
        tasks.append(asyncio.create_task(_guarded("host.psutil", _check_psutil_optional(), "info")))

    await asyncio.gather(*tasks)

    total_ms = _ms(time.monotonic() - t0)
    summary = _summarize(results, total_ms)

    finished_at = _utcnow_iso()
    report = RunReport(
        run_id=str(run_id),
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=total_ms,
        host=_host_info(),
        python=_python_info(),
        config=dict(config),
        results=sorted(results, key=lambda r: (r.severity, r.name)),
        summary=summary,
    )
    return report


def _to_json(report: RunReport) -> str:
    def _default(o: Any) -> Any:
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        return str(o)

    return json.dumps(report, ensure_ascii=False, indent=2, default=_default, sort_keys=True)


def build_default_config_from_env() -> Dict[str, Any]:
    # No claims about "correctness" of values: only deterministic mapping from env to config.
    return {
        "run_id": _env_str("AGENT_MASH_QC_RUN_ID", ""),
        "timeout_s": float(_env_int("AGENT_MASH_QC_TIMEOUT_S", 2)),
        "concurrency": int(_env_int("AGENT_MASH_QC_CONCURRENCY", 8)),
        "include_psutil": _env_bool("AGENT_MASH_QC_INCLUDE_PSUTIL", True),
        "required_env": [s for s in _env_str("AGENT_MASH_QC_REQUIRED_ENV", "").split(",") if s.strip()],
        "fs_paths": [s for s in _env_str("AGENT_MASH_QC_FS_PATHS", "").split(",") if s.strip()],
        "import_modules": [s for s in _env_str("AGENT_MASH_QC_IMPORTS", "").split(",") if s.strip()],
        "dns_hosts": [s for s in _env_str("AGENT_MASH_QC_DNS_HOSTS", "localhost").split(",") if s.strip()],
        "tcp_endpoints": [s for s in _env_str("AGENT_MASH_QC_TCP", "").split(",") if s.strip()],
        "https_urls": [s for s in _env_str("AGENT_MASH_QC_HTTPS", "").split(",") if s.strip()],
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="agent_mash.quick_check", add_help=True)
    p.add_argument("--timeout-s", type=float, default=None)
    p.add_argument("--concurrency", type=int, default=None)
    p.add_argument("--include-psutil", action="store_true", default=None)
    p.add_argument("--no-psutil", action="store_true", default=None)
    p.add_argument("--required-env", type=str, default=None, help="comma-separated env var names")
    p.add_argument("--fs-paths", type=str, default=None, help="comma-separated paths to check")
    p.add_argument("--imports", type=str, default=None, help="comma-separated python modules to import")
    p.add_argument("--dns-hosts", type=str, default=None, help="comma-separated hosts to resolve")
    p.add_argument("--tcp", type=str, default=None, help="comma-separated host:port endpoints")
    p.add_argument("--https", type=str, default=None, help="comma-separated https:// URLs to probe")
    p.add_argument("--output", type=str, default=None, help="write JSON report to file")

    args = p.parse_args(list(argv) if argv is not None else None)

    cfg = build_default_config_from_env()

    if args.timeout_s is not None:
        cfg["timeout_s"] = float(args.timeout_s)
    if args.concurrency is not None:
        cfg["concurrency"] = int(args.concurrency)

    if args.include_psutil is True:
        cfg["include_psutil"] = True
    if args.no_psutil is True:
        cfg["include_psutil"] = False

    if args.required_env is not None:
        cfg["required_env"] = [s for s in args.required_env.split(",") if s.strip()]
    if args.fs_paths is not None:
        cfg["fs_paths"] = [s for s in args.fs_paths.split(",") if s.strip()]
    if args.imports is not None:
        cfg["import_modules"] = [s for s in args.imports.split(",") if s.strip()]
    if args.dns_hosts is not None:
        cfg["dns_hosts"] = [s for s in args.dns_hosts.split(",") if s.strip()]
    if args.tcp is not None:
        cfg["tcp_endpoints"] = [s for s in args.tcp.split(",") if s.strip()]
    if args.https is not None:
        cfg["https_urls"] = [s for s in args.https.split(",") if s.strip()]

    try:
        report = asyncio.run(run_quick_check(cfg))
        out = _to_json(report)

        if args.output:
            ap = os.path.abspath(args.output)
            os.makedirs(os.path.dirname(ap), exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix="quick_check_", suffix=".tmp", dir=os.path.dirname(ap), text=True)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(out)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, ap)
            finally:
                try:
                    if os.path.exists(tmp):
                        os.remove(tmp)
                except Exception:
                    pass
        else:
            sys.stdout.write(out + "\n")

        return _exit_code(report.summary)
    except Exception:
        tb = traceback.format_exc()
        sys.stderr.write(_truncate(tb, 8000) + "\n")
        return ExitCode.INTERNAL_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
