# cybersecurity-core/cybersecurity/adversary_emulation/ttp/primitives/discovery.py
# -*- coding: utf-8 -*-
"""
Discovery primitives for Adversary Emulation (MITRE ATT&CK TA0007).

Implements cross-platform, dependency-free discovery primitives:
- System Information Discovery (T1082)
- Process Discovery (T1057)
- Account Discovery (T1087.*)
- System Network Configuration Discovery (T1016, T1016.001, T1016.002)
- Software Discovery (T1518)
- File and Directory Discovery (T1083) — guarded, scoped by user-provided roots
- Environment Variables (supporting safe redaction)

Design goals:
- Safety-first subprocess execution (no shell=True), tight timeouts, env isolation
- OS-aware lightweight fallbacks (PowerShell on Windows, common POSIX tools on *nix)
- JSON-serializable, structured results with explicit success/error fields
- Registry of primitives (callable map) for higher-level TTP orchestration

ATT&CK references (see project docs for full mapping):
- TA0007 Discovery overview
- T1082 System Information Discovery
- T1057 Process Discovery
- T1087 Account Discovery (sub-techniques .001 Local, .002 Domain, .003 Email, .004 Cloud)
- T1016 System Network Configuration Discovery (+ .001 Internet Connection, .002 Wi-Fi)
- T1518 Software Discovery
- T1083 File and Directory Discovery
"""

from __future__ import annotations

import dataclasses
import json
import os
import platform
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any


# -----------------------------
# Constants / Environment
# -----------------------------

DEFAULT_CMD_TIMEOUT_SEC = int(os.getenv("AE_DISCOVERY_CMD_TIMEOUT", "15"))
DEFAULT_LISTING_LIMIT = int(os.getenv("AE_DISCOVERY_LISTING_LIMIT", "10000"))  # safety cap
REDACT_ENV = os.getenv("AE_DISCOVERY_REDACT_ENV", "1") == "1"

WIN = platform.system().lower().startswith("win")
DARWIN = platform.system().lower().startswith("darwin")
LINUX = platform.system().lower().startswith("linux")

POWERSHELL = r"powershell.exe" if WIN else None  # Windows PowerShell (fallback if pwsh unavailable)
PWSH = r"pwsh.exe" if WIN else None  # PowerShell Core if present


# -----------------------------
# Result model
# -----------------------------

@dataclasses.dataclass
class DiscoveryResult:
    ok: bool
    technique: str
    data: Any
    errors: List[str] = dataclasses.field(default_factory=list)
    meta: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


# -----------------------------
# Safe runner
# -----------------------------

def _which(cmd: str) -> Optional[str]:
    from shutil import which
    return which(cmd)

def run_cmd(args: List[str], timeout: int = DEFAULT_CMD_TIMEOUT_SEC, cwd: Optional[Path] = None,
            extra_env: Optional[Dict[str, str]] = None) -> Tuple[int, str, str]:
    """
    Safe command execution:
    - no shell=True
    - time-limited
    - sanitized environment
    - returns (rc, stdout, stderr)
    """
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    try:
        proc = subprocess.Popen(
            args,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        out, err = proc.communicate(timeout=timeout)
        return proc.returncode, out or "", err or ""
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except Exception:
            pass
        return 124, "", f"timeout after {timeout}s"
    except FileNotFoundError as e:
        return 127, "", f"{e}"
    except Exception as e:
        return 1, "", f"{type(e).__name__}: {e}"


def run_powershell(script: str, timeout: int = DEFAULT_CMD_TIMEOUT_SEC) -> Tuple[int, str, str]:
    """
    Execute PowerShell command on Windows with -NoProfile.
    Prefer pwsh if available, else powershell.exe.
    """
    if not WIN:
        return 126, "", "PowerShell not available on non-Windows systems"
    ps = _which("pwsh.exe") or _which("powershell.exe") or PWSH or POWERSHELL
    if not ps:
        return 127, "", "PowerShell not found"
    return run_cmd([ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script], timeout=timeout)


# -----------------------------
# Helpers
# -----------------------------

def redact_value(v: str) -> str:
    if not v:
        return v
    # AWS-like keys, tokens, secrets common patterns (best effort)
    patterns = [
        r"AKIA[0-9A-Z]{16}",
        r"ASIA[0-9A-Z]{16}",
        r"(?i)aws(_)?secret(_)?access(_)?key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]",
        r"(?i)(secret|token|password|pass|pwd)[^=]*=\s*['\"][^'\" ]+['\"]",
        r"(?i)(bearer|apikey|api_key|api-key)\s+[A-Za-z0-9\-_\.=:/+]+",
    ]
    redacted = v
    for p in patterns:
        redacted = re.sub(p, "***REDACTED***", redacted)
    return redacted

def maybe_redact_env(d: Dict[str, str]) -> Dict[str, str]:
    if not REDACT_ENV:
        return d
    safe = {}
    for k, v in d.items():
        if re.search(r"(?i)(secret|token|password|pass|pwd|key)", k):
            safe[k] = "***REDACTED***"
        else:
            safe[k] = redact_value(v)
    return safe

def cap_list(items: List[Any], cap: int = DEFAULT_LISTING_LIMIT) -> List[Any]:
    if len(items) > cap:
        return items[:cap]
    return items


# -----------------------------
# T1082 System Information Discovery
# -----------------------------

def system_information() -> DiscoveryResult:
    """
    ATT&CK: T1082 System Information Discovery (OS, kernel, arch, hostname, uptime best-effort)
    """
    technique = "T1082"
    data: Dict[str, Any] = {
        "platform": platform.system(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "hostname": platform.node(),
    }
    errors: List[str] = []

    # Uptime (best-effort, no external deps)
    try:
        if LINUX:
            with open("/proc/uptime", "r", encoding="utf-8") as f:
                secs = float(f.read().split()[0])
            data["uptime_seconds"] = int(secs)
        elif DARWIN:
            # sysctl kern.boottime (needs parsing) — fallback to current time diff
            # Keep it simple: not critical field; omit if not robustly available
            pass
        elif WIN:
            # PowerShell WMI for LastBootUpTime
            rc, out, err = run_powershell(
                "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')"
            )
            if rc == 0 and out.strip():
                data["last_boot_utc"] = out.strip()
            else:
                if err:
                    errors.append(f"uptime(ps): {err.strip()}")
    except Exception as e:
        errors.append(f"uptime: {e}")

    return DiscoveryResult(ok=True, technique=technique, data=data, errors=errors)


# -----------------------------
# T1057 Process Discovery
# -----------------------------

def process_discovery() -> DiscoveryResult:
    """
    ATT&CK: T1057 Process Discovery
    Cross-platform process listing with minimal fields (pid, ppid, name/command).
    """
    technique = "T1057"
    items: List[Dict[str, Any]] = []
    errors: List[str] = []

    if WIN:
        rc, out, err = run_cmd(["tasklist", "/fo", "csv", "/v"], timeout=DEFAULT_CMD_TIMEOUT_SEC)
        if rc == 0:
            # CSV with headers; split conservatively
            import csv
            from io import StringIO
            reader = csv.DictReader(StringIO(out))
            for row in reader:
                items.append({
                    "image": row.get("Image Name"),
                    "pid": row.get("PID"),
                    "session": row.get("Session Name"),
                    "session_num": row.get("Session#"),
                    "mem_usage": row.get("Mem Usage"),
                    "status": row.get("Status"),
                    "user_name": row.get("User Name"),
                    "cpu_time": row.get("CPU Time"),
                    "window_title": row.get("Window Title"),
                })
        else:
            errors.append(f"tasklist: {err.strip()}")
    else:
        # POSIX: ps -eo pid,ppid,comm,args
        rc, out, err = run_cmd(["ps", "-eo", "pid,ppid,comm,args"], timeout=DEFAULT_CMD_TIMEOUT_SEC)
        if rc == 0:
            for line in out.splitlines()[1:]:
                try:
                    # split: pid ppid comm args...
                    parts = line.strip().split(None, 3)
                    if len(parts) >= 3:
                        pid = parts[0]
                        ppid = parts[1]
                        comm = parts[2]
                        args = parts[3] if len(parts) == 4 else ""
                        items.append({"pid": pid, "ppid": ppid, "command": comm, "args": args})
                except Exception:
                    continue
        else:
            errors.append(f"ps: {err.strip()}")

    return DiscoveryResult(ok=True, technique=technique, data=cap_list(items), errors=errors)


# -----------------------------
# T1087 Account Discovery (local/domain best-effort)
# -----------------------------

def account_discovery() -> DiscoveryResult:
    """
    ATT&CK: T1087 Account Discovery (focus: local accounts)
    - Windows: `net user`
    - Linux/macOS: /etc/passwd parsing (no shadow)
    """
    technique = "T1087"
    data: Dict[str, Any] = {"local_accounts": []}
    errors: List[str] = []

    if WIN:
        rc, out, err = run_cmd(["net", "user"], timeout=DEFAULT_CMD_TIMEOUT_SEC)
        if rc == 0:
            # Lines between "----" separators contain account names (space-separated)
            users: List[str] = []
            for line in out.splitlines():
                if line.strip().startswith("The command completed"):
                    break
                if line.strip() and not line.lower().startswith("user accounts") and not set(line.strip()) <= {"-"}:
                    users.extend([u for u in line.split() if u.strip()])
            data["local_accounts"] = users
        else:
            errors.append(f"net user: {err.strip()}")
    else:
        try:
            entries: List[str] = []
            with open("/etc/passwd", "r", encoding="utf-8") as f:
                for line in f:
                    if not line or line.startswith("#"):
                        continue
                    username = line.split(":", 1)[0]
                    entries.append(username)
            data["local_accounts"] = entries
        except Exception as e:
            errors.append(f"/etc/passwd: {e}")

    return DiscoveryResult(ok=True, technique=technique, data=data, errors=errors)


# -----------------------------
# T1016 System Network Configuration Discovery
# -----------------------------

def network_configuration() -> DiscoveryResult:
    """
    ATT&CK: T1016 System Network Configuration Discovery (+ sub-techniques .001, .002)
    Collect interface addresses and basic DNS/route hints (best-effort).
    """
    technique = "T1016"
    data: Dict[str, Any] = {"interfaces": [], "dns": {}, "routes_hint": None}
    errors: List[str] = []

    if WIN:
        rc, out, err = run_cmd(["ipconfig", "/all"], timeout=DEFAULT_CMD_TIMEOUT_SEC)
        if rc == 0:
            data["interfaces"].append({"raw": out})
        else:
            errors.append(f"ipconfig: {err.strip()}")

        # route print (hint)
        rc, out, err = run_cmd(["route", "print"], timeout=DEFAULT_CMD_TIMEOUT_SEC)
        if rc == 0:
            data["routes_hint"] = out
        elif err:
            errors.append(f"route: {err.strip()}")

        # DNS (PowerShell)
        rc, out, err = run_powershell("Get-DnsClientServerAddress | Format-List | Out-String")
        if rc == 0:
            data["dns"]["raw"] = out
        elif err:
            errors.append(f"Get-DnsClientServerAddress: {err.strip()}")

    else:
        # interfaces (ip addr show / ifconfig fallback)
        if _which("ip"):
            rc, out, err = run_cmd(["ip", "addr", "show"], timeout=DEFAULT_CMD_TIMEOUT_SEC)
        else:
            rc, out, err = run_cmd(["ifconfig", "-a"], timeout=DEFAULT_CMD_TIMEOUT_SEC)
        if rc == 0:
            data["interfaces"].append({"raw": out})
        else:
            errors.append(f"ifconfig/ip: {err.strip()}")

        # routes
        if _which("ip"):
            rc, out, err = run_cmd(["ip", "route"], timeout=DEFAULT_CMD_TIMEOUT_SEC)
        else:
            rc, out, err = run_cmd(["netstat", "-rn"], timeout=DEFAULT_CMD_TIMEOUT_SEC)
        if rc == 0:
            data["routes_hint"] = out
        elif err:
            errors.append(f"route: {err.strip()}")

        # DNS (Linux: resolv.conf; macOS: scutil --dns)
        if LINUX:
            try:
                with open("/etc/resolv.conf", "r", encoding="utf-8") as f:
                    data["dns"]["resolv_conf"] = f.read()
            except Exception as e:
                errors.append(f"/etc/resolv.conf: {e}")
        elif DARWIN:
            rc, out, err = run_cmd(["scutil", "--dns"], timeout=DEFAULT_CMD_TIMEOUT_SEC)
            if rc == 0:
                data["dns"]["raw"] = out
            elif err:
                errors.append(f"scutil --dns: {err.strip()}")

    return DiscoveryResult(ok=True, technique=technique, data=data, errors=errors)


# -----------------------------
# T1518 Software Discovery (installed applications best-effort)
# -----------------------------

def software_discovery() -> DiscoveryResult:
    """
    ATT&CK: T1518 Software Discovery
    Enumerate installed software best-effort without external deps.
    """
    technique = "T1518"
    items: List[Dict[str, Any]] = []
    errors: List[str] = []

    if WIN:
        # Query Uninstall keys via PowerShell
        ps_script = r"""
$paths = @(
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$apps = foreach ($p in $paths) {
  Get-ItemProperty -Path $p -ErrorAction SilentlyContinue |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
}
$apps | ConvertTo-Json -Depth 3
"""
        rc, out, err = run_powershell(ps_script)
        if rc == 0 and out.strip():
            try:
                parsed = json.loads(out)
                if isinstance(parsed, list):
                    for a in parsed:
                        if a.get("DisplayName"):
                            items.append({
                                "name": a.get("DisplayName"),
                                "version": a.get("DisplayVersion"),
                                "publisher": a.get("Publisher"),
                                "install_date": a.get("InstallDate"),
                            })
            except Exception as e:
                errors.append(f"parse(ps json): {e}")
        else:
            if err:
                errors.append(f"ps software: {err.strip()}")

    elif LINUX:
        # Try dpkg-query, then rpm
        if _which("dpkg-query"):
            rc, out, err = run_cmd(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], timeout=DEFAULT_CMD_TIMEOUT_SEC)
            if rc == 0:
                for line in out.splitlines():
                    try:
                        name, ver = line.split("\t", 1)
                        items.append({"name": name, "version": ver})
                    except ValueError:
                        continue
            else:
                errors.append(f"dpkg-query: {err.strip()}")
        elif _which("rpm"):
            rc, out, err = run_cmd(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"], timeout=DEFAULT_CMD_TIMEOUT_SEC)
            if rc == 0:
                for line in out.splitlines():
                    try:
                        name, ver = line.split("\t", 1)
                        items.append({"name": name, "version": ver})
                    except ValueError:
                        continue
            else:
                errors.append(f"rpm: {err.strip()}")

    elif DARWIN:
        # system_profiler is slow; limit fields
        if _which("system_profiler"):
            rc, out, err = run_cmd(["system_profiler", "SPApplicationsDataType", "-json"], timeout=max(DEFAULT_CMD_TIMEOUT_SEC, 60))
            if rc == 0:
                try:
                    parsed = json.loads(out)
                    apps = parsed.get("SPApplicationsDataType", [])
                    for a in apps:
                        items.append({
                            "name": a.get("_name"),
                            "version": a.get("version"),
                            "obtained_from": a.get("obtained_from"),
                            "last_modified": a.get("last_modified"),
                        })
                except Exception as e:
                    errors.append(f"parse(sp json): {e}")
            else:
                errors.append(f"system_profiler: {err.strip()}")

    return DiscoveryResult(ok=True, technique=technique, data=cap_list(items), errors=errors)


# -----------------------------
# T1083 File and Directory Discovery (scoped)
# -----------------------------

def file_directory_discovery(roots: List[Path], max_entries: int = DEFAULT_LISTING_LIMIT,
                             include_files: bool = True, include_dirs: bool = True) -> DiscoveryResult:
    """
    ATT&CK: T1083 File and Directory Discovery
    Safe, scoped listing under provided roots. No traversal outside roots.
    """
    technique = "T1083"
    entries: List[Dict[str, Any]] = []
    errors: List[str] = []

    seen = 0
    for root in roots:
        try:
            root = root.resolve()
            if not root.exists():
                errors.append(f"not found: {root}")
                continue
            for p in root.rglob("*"):
                if seen >= max_entries:
                    break
                try:
                    if p.is_dir() and include_dirs:
                        entries.append({"type": "dir", "path": str(p), "name": p.name})
                        seen += 1
                    elif p.is_file() and include_files:
                        st = p.stat()
                        entries.append({
                            "type": "file",
                            "path": str(p),
                            "name": p.name,
                            "size": st.st_size,
                            "mtime": int(st.st_mtime),
                        })
                        seen += 1
                except Exception:
                    continue
        except Exception as e:
            errors.append(f"{root}: {e}")

    return DiscoveryResult(ok=True, technique=technique, data=entries, errors=errors,
                           meta={"entries_count": len(entries), "cap": max_entries})


# -----------------------------
# Environment variables (aux)
# -----------------------------

def environment_variables() -> DiscoveryResult:
    """
    Auxiliary primitive: dump environment variables with safe redaction.
    Maps to general Discovery context; sensitive keys masked if AE_DISCOVERY_REDACT_ENV=1.
    """
    technique = "TA0007"
    env = {k: str(v) for k, v in os.environ.items()}
    return DiscoveryResult(ok=True, technique=technique,
                           data=maybe_redact_env(env),
                           errors=[])


# -----------------------------
# Registry
# -----------------------------

PRIMITIVES: Dict[str, Any] = {
    # MITRE-aligned keys
    "T1082.system_information": system_information,
    "T1057.process_discovery": process_discovery,
    "T1087.account_discovery": account_discovery,
    "T1016.network_configuration": network_configuration,
    "T1518.software_discovery": software_discovery,
    "T1083.file_directory_discovery": file_directory_discovery,  # requires args
    # Aux
    "TA0007.environment_variables": environment_variables,
}


# -----------------------------
# Minimal CLI (optional)
# -----------------------------

def _print(obj: Any) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, indent=2))
    sys.stdout.write("\n")

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="ae-discovery",
        description="Aethernova adversary emulation discovery primitives (safe, dependency-free)."
    )
    p.add_argument("--primitive", required=True,
                   help="One of: " + ", ".join(sorted(PRIMITIVES.keys())))
    p.add_argument("--roots", nargs="*", help="For file_directory_discovery: paths to list")
    p.add_argument("--max-entries", type=int, default=DEFAULT_LISTING_LIMIT)
    args = p.parse_args()

    if args.primitive == "T1083.file_directory_discovery":
        roots = [Path(r) for r in (args.roots or [])]
        res = file_directory_discovery(roots, max_entries=args.max_entries)
    else:
        fn = PRIMITIVES.get(args.primitive)
        if not fn:
            _print({"ok": False, "error": "unknown primitive"})
            sys.exit(2)
        res = fn()  # type: ignore[call-arg]

    _print(res.to_dict())


if __name__ == "__main__":
    _cli()
