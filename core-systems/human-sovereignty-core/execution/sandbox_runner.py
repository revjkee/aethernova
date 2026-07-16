# human-sovereignty-core/execution/sandbox_runner.py
from __future__ import annotations

import dataclasses
import datetime as _dt
import errno
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union


# =========================
# Policy and result models
# =========================

@dataclass(frozen=True)
class SandboxPolicy:
    """
    Sandbox execution policy.
    This module provides best-effort isolation using OS primitives where available.
    It does not claim full VM-grade isolation.
    """

    # Execution
    timeout_seconds: int = 30
    kill_grace_seconds: int = 2
    cwd_mode: str = "tempdir"  # tempdir | provided
    umask: int = 0o077

    # Allowlist / Denylist
    require_allowlist: bool = True
    allowed_binaries: Tuple[str, ...] = (
        "python",
        "python3",
        "bash",
        "sh",
        "node",
        "npm",
        "npx",
        "git",
        "make",
        "cmake",
    )
    denied_substrings: Tuple[str, ...] = (
        "rm -rf /",
        "mkfs",
        "dd if=",
        "shutdown",
        "reboot",
        "poweroff",
        "sudo",
        "su ",
        "chmod 777",
        "chown root",
    )

    # Resource limits (best-effort, POSIX only)
    limit_cpu_seconds: int = 15
    limit_address_space_mb: int = 512
    limit_file_size_mb: int = 64
    limit_open_files: int = 256
    limit_processes: int = 64
    limit_core_dumps: bool = True

    # IO capture
    max_output_bytes: int = 1024 * 1024  # 1 MiB combined best-effort

    # Environment hygiene
    inherit_env: bool = False
    allowed_env_keys: Tuple[str, ...] = (
        "LANG",
        "LC_ALL",
        "PATH",
        "PYTHONIOENCODING",
        "PYTHONUTF8",
        "NODE_OPTIONS",
    )
    default_env: Dict[str, str] = dataclasses.field(
        default_factory=lambda: {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUTF8": "1",
            "PATH": os.environ.get("PATH", ""),
        }
    )

    # Hardening switches
    disallow_network: bool = True
    # If True, will FAIL when it cannot enforce network isolation with OS primitives.
    require_network_isolation_enforced: bool = False


@dataclass(frozen=True)
class RunRequest:
    argv: List[str]
    stdin_text: Optional[str] = None
    cwd: Optional[str] = None
    extra_env: Optional[Dict[str, str]] = None
    artifacts_dir: Optional[str] = None
    label: str = "sandbox_run"
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclass(frozen=True)
class RunResult:
    started_utc: str
    finished_utc: str
    duration_ms: int
    ok: bool
    status: str  # PASS | FAIL | TIMEOUT | POLICY_DENY | ERROR
    return_code: Optional[int]
    stdout: str
    stderr: str
    sandbox_dir: str
    artifacts_dir: str
    policy_applied: Dict[str, Any]
    diagnostics: Dict[str, Any]


# =========================
# Errors
# =========================

class SandboxError(Exception):
    pass


class PolicyDenied(SandboxError):
    pass


class NetworkIsolationUnavailable(SandboxError):
    pass


# =========================
# Helpers
# =========================

_TIME_FMT = "%Y-%m-%dT%H:%M:%SZ"


def _utc_now_z() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).replace(microsecond=0).strftime(_TIME_FMT)


def _ms(dt0: _dt.datetime, dt1: _dt.datetime) -> int:
    return int((dt1 - dt0).total_seconds() * 1000)


def _is_posix() -> bool:
    return os.name == "posix"


def _norm_text(s: str) -> str:
    return " ".join(s.strip().split())


def _argv_to_display(argv: Sequence[str]) -> str:
    return " ".join(argv)


def _truncate_bytes(text: str, max_bytes: int) -> str:
    b = text.encode("utf-8", errors="replace")
    if len(b) <= max_bytes:
        return text
    cut = b[:max_bytes]
    return cut.decode("utf-8", errors="replace")


def _safe_mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _which(binary: str, env: Dict[str, str]) -> Optional[str]:
    # shutil.which uses current env by default; we pass sanitized env via PATH.
    return shutil.which(binary, path=env.get("PATH"))


def _sanitize_env(policy: SandboxPolicy, extra_env: Optional[Dict[str, str]]) -> Dict[str, str]:
    base: Dict[str, str] = {}
    if policy.inherit_env:
        base.update({k: v for k, v in os.environ.items()})
    base.update({k: v for k, v in policy.default_env.items()})

    if extra_env:
        for k, v in extra_env.items():
            if not isinstance(k, str) or not isinstance(v, str):
                continue
            base[k] = v

    # allowlist env keys only
    allowed = set(policy.allowed_env_keys)
    sanitized: Dict[str, str] = {}
    for k, v in base.items():
        if k in allowed:
            sanitized[k] = v
    # Ensure PATH exists
    sanitized["PATH"] = base.get("PATH", "")
    return sanitized


def _policy_check_command(policy: SandboxPolicy, argv: Sequence[str], env: Dict[str, str]) -> Dict[str, Any]:
    if not argv or not isinstance(argv[0], str) or not argv[0].strip():
        raise PolicyDenied("Empty argv[0]")

    cmd0 = argv[0].strip()

    # allowlist enforcement
    resolved = None
    if os.sep in cmd0 or (os.altsep and os.altsep in cmd0):
        resolved = str(Path(cmd0).expanduser().resolve())
        bin_name = Path(resolved).name
    else:
        bin_name = cmd0
        resolved = _which(bin_name, env)

    if policy.require_allowlist:
        if bin_name not in set(policy.allowed_binaries):
            raise PolicyDenied(f"Binary not allowed: {bin_name}")
        if resolved is None:
            raise PolicyDenied(f"Binary not found in PATH: {bin_name}")

    # denylist substrings (simple but effective)
    joined = _norm_text(_argv_to_display(argv))
    for bad in policy.denied_substrings:
        if bad and bad in joined:
            raise PolicyDenied(f"Denied pattern detected: {bad}")

    return {
        "bin": bin_name,
        "bin_resolved": resolved,
        "argv_display": joined,
        "allowlist_enforced": policy.require_allowlist,
        "denylist_checked": True,
    }


def _posix_preexec_fn(policy: SandboxPolicy, sandbox_dir: Path) -> Any:
    # Applied in child process before exec.
    def _fn() -> None:
        try:
            os.umask(policy.umask)
        except Exception:
            pass

        # Isolate process group, so we can kill children
        try:
            os.setsid()
        except Exception:
            pass

        # Best-effort niceness
        try:
            os.nice(10)
        except Exception:
            pass

        # Resource limits (POSIX)
        try:
            import resource  # POSIX only
        except Exception:
            resource = None

        if resource is not None:
            try:
                resource.setrlimit(resource.RLIMIT_CPU, (policy.limit_cpu_seconds, policy.limit_cpu_seconds))
            except Exception:
                pass

            # Address space
            try:
                as_bytes = int(policy.limit_address_space_mb) * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (as_bytes, as_bytes))
            except Exception:
                pass

            # File size
            try:
                fs_bytes = int(policy.limit_file_size_mb) * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_FSIZE, (fs_bytes, fs_bytes))
            except Exception:
                pass

            # Open files
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (policy.limit_open_files, policy.limit_open_files))
            except Exception:
                pass

            # Processes
            if hasattr(resource, "RLIMIT_NPROC"):
                try:
                    resource.setrlimit(resource.RLIMIT_NPROC, (policy.limit_processes, policy.limit_processes))
                except Exception:
                    pass

            # Core dumps
            if policy.limit_core_dumps and hasattr(resource, "RLIMIT_CORE"):
                try:
                    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                except Exception:
                    pass

        # Constrain cwd explicitly
        try:
            os.chdir(str(sandbox_dir))
        except Exception:
            pass

        # Best-effort: prevent accidental access to parent by tightening permissions on sandbox root.
        try:
            os.chmod(str(sandbox_dir), 0o700)
        except Exception:
            pass

    return _fn


def _kill_process_tree_posix(p: subprocess.Popen, grace: int) -> None:
    try:
        pgid = os.getpgid(p.pid)
    except Exception:
        pgid = None

    if pgid is not None:
        try:
            os.killpg(pgid, signal.SIGTERM)
        except Exception:
            pass
    else:
        try:
            p.terminate()
        except Exception:
            pass

    t_end = time.time() + max(0, grace)
    while time.time() < t_end:
        if p.poll() is not None:
            return
        time.sleep(0.05)

    if pgid is not None:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except Exception:
            pass
    else:
        try:
            p.kill()
        except Exception:
            pass


def _kill_process_tree_windows(p: subprocess.Popen) -> None:
    try:
        p.kill()
    except Exception:
        pass


def _enforce_network_isolation(policy: SandboxPolicy) -> Dict[str, Any]:
    """
    Best-effort network isolation:
    - This module does not implement full network namespaces because it typically requires privileges.
    - We provide a detection mechanism and an optional hard requirement.
    """
    info: Dict[str, Any] = {
        "requested_disallow_network": policy.disallow_network,
        "enforced": False,
        "method": None,
        "note": None,
    }

    if not policy.disallow_network:
        info["note"] = "network_allowed_by_policy"
        return info

    # Without elevated privileges, we cannot reliably enforce no-network at OS level here.
    info["note"] = "no_os_level_network_isolation_applied"
    if policy.require_network_isolation_enforced:
        raise NetworkIsolationUnavailable("Network isolation enforcement not available in this runner")
    return info


# =========================
# Runner
# =========================

class SandboxRunner:
    def __init__(self, policy: Optional[SandboxPolicy] = None):
        self.policy = policy or SandboxPolicy()

    def run(self, req: RunRequest) -> RunResult:
        start_dt = _dt.datetime.now(tz=_dt.timezone.utc)
        started = start_dt.replace(microsecond=0).strftime(_TIME_FMT)

        policy = self.policy

        env = _sanitize_env(policy, req.extra_env)

        policy_applied: Dict[str, Any] = {
            "timeout_seconds": policy.timeout_seconds,
            "kill_grace_seconds": policy.kill_grace_seconds,
            "umask": oct(policy.umask),
            "limits": {
                "cpu_seconds": policy.limit_cpu_seconds,
                "address_space_mb": policy.limit_address_space_mb,
                "file_size_mb": policy.limit_file_size_mb,
                "open_files": policy.limit_open_files,
                "processes": policy.limit_processes,
                "core_dumps_disabled": bool(policy.limit_core_dumps),
            },
            "env_policy": {
                "inherit_env": policy.inherit_env,
                "allowed_env_keys": list(policy.allowed_env_keys),
            },
            "allowlist": {
                "require_allowlist": policy.require_allowlist,
                "allowed_binaries": list(policy.allowed_binaries),
            },
        }

        diagnostics: Dict[str, Any] = {
            "label": req.label,
            "metadata": req.metadata,
            "system": {
                "os": os.name,
                "platform": platform.platform(),
                "python": sys.version,
            },
        }

        stdout_text = ""
        stderr_text = ""
        return_code: Optional[int] = None
        status = "ERROR"
        ok = False

        # Prepare sandbox dirs
        sandbox_dir: Path
        if policy.cwd_mode == "provided" and req.cwd:
            sandbox_dir = Path(req.cwd).expanduser().resolve()
            _safe_mkdir(sandbox_dir)
        else:
            sandbox_dir = Path(tempfile.mkdtemp(prefix="hs_sandbox_")).resolve()

        artifacts_dir = Path(req.artifacts_dir).expanduser().resolve() if req.artifacts_dir else (sandbox_dir / "artifacts")
        _safe_mkdir(artifacts_dir)

        diagnostics["paths"] = {
            "sandbox_dir": str(sandbox_dir),
            "artifacts_dir": str(artifacts_dir),
        }

        # Network isolation (best-effort)
        try:
            net_info = _enforce_network_isolation(policy)
            policy_applied["network"] = net_info
        except NetworkIsolationUnavailable as e:
            end_dt = _dt.datetime.now(tz=_dt.timezone.utc)
            finished = end_dt.replace(microsecond=0).strftime(_TIME_FMT)
            return RunResult(
                started_utc=started,
                finished_utc=finished,
                duration_ms=_ms(start_dt, end_dt),
                ok=False,
                status="POLICY_DENY",
                return_code=None,
                stdout="",
                stderr=str(e),
                sandbox_dir=str(sandbox_dir),
                artifacts_dir=str(artifacts_dir),
                policy_applied=policy_applied,
                diagnostics=diagnostics,
            )

        # Policy checks for command
        try:
            cmd_info = _policy_check_command(policy, req.argv, env)
            policy_applied["command"] = cmd_info
        except PolicyDenied as e:
            end_dt = _dt.datetime.now(tz=_dt.timezone.utc)
            finished = end_dt.replace(microsecond=0).strftime(_TIME_FMT)
            return RunResult(
                started_utc=started,
                finished_utc=finished,
                duration_ms=_ms(start_dt, end_dt),
                ok=False,
                status="POLICY_DENY",
                return_code=None,
                stdout="",
                stderr=str(e),
                sandbox_dir=str(sandbox_dir),
                artifacts_dir=str(artifacts_dir),
                policy_applied=policy_applied,
                diagnostics=diagnostics,
            )

        # Execute
        try:
            stdin_bytes = None
            if req.stdin_text is not None:
                stdin_bytes = req.stdin_text.encode("utf-8", errors="replace")

            preexec = _posix_preexec_fn(policy, sandbox_dir) if _is_posix() else None

            p = subprocess.Popen(
                req.argv,
                cwd=str(sandbox_dir),
                env=env,
                stdin=subprocess.PIPE if stdin_bytes is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=preexec,
                text=False,
            )

            try:
                out_b, err_b = p.communicate(input=stdin_bytes, timeout=policy.timeout_seconds)
                return_code = p.returncode
                stdout_text = out_b.decode("utf-8", errors="replace") if out_b else ""
                stderr_text = err_b.decode("utf-8", errors="replace") if err_b else ""

                # Bound output size
                combined = stdout_text + stderr_text
                if len(combined.encode("utf-8", errors="replace")) > policy.max_output_bytes:
                    stdout_text = _truncate_bytes(stdout_text, policy.max_output_bytes // 2)
                    stderr_text = _truncate_bytes(stderr_text, policy.max_output_bytes // 2)
                    diagnostics["output_truncated"] = True
                else:
                    diagnostics["output_truncated"] = False

                ok = return_code == 0
                status = "PASS" if ok else "FAIL"

            except subprocess.TimeoutExpired:
                status = "TIMEOUT"
                ok = False
                try:
                    if _is_posix():
                        _kill_process_tree_posix(p, policy.kill_grace_seconds)
                    else:
                        _kill_process_tree_windows(p)
                except Exception:
                    pass

                # Collect remaining outputs best-effort
                try:
                    out_b, err_b = p.communicate(timeout=1)
                except Exception:
                    out_b, err_b = b"", b""

                return_code = p.returncode
                stdout_text = out_b.decode("utf-8", errors="replace") if out_b else ""
                stderr_text = err_b.decode("utf-8", errors="replace") if err_b else ""

        except FileNotFoundError as e:
            status = "ERROR"
            ok = False
            return_code = None
            stdout_text = ""
            stderr_text = f"FileNotFoundError: {e}"
        except PermissionError as e:
            status = "ERROR"
            ok = False
            return_code = None
            stdout_text = ""
            stderr_text = f"PermissionError: {e}"
        except OSError as e:
            status = "ERROR"
            ok = False
            return_code = None
            stdout_text = ""
            stderr_text = f"OSError: {e} (errno={getattr(e, 'errno', None)})"
        except Exception as e:
            status = "ERROR"
            ok = False
            return_code = None
            stdout_text = ""
            stderr_text = f"Exception: {repr(e)}"

        # Persist artifacts
        try:
            report_path = artifacts_dir / "sandbox_run_report.json"
            report_obj = {
                "started_utc": started,
                "finished_utc": _utc_now_z(),
                "status": status,
                "ok": ok,
                "return_code": return_code,
                "argv": req.argv,
                "sandbox_dir": str(sandbox_dir),
                "artifacts_dir": str(artifacts_dir),
                "policy_applied": policy_applied,
                "diagnostics": diagnostics,
            }
            report_path.write_text(json.dumps(report_obj, ensure_ascii=False, sort_keys=True, indent=2), encoding="utf-8")

            (artifacts_dir / "stdout.txt").write_text(stdout_text, encoding="utf-8", errors="replace")
            (artifacts_dir / "stderr.txt").write_text(stderr_text, encoding="utf-8", errors="replace")
        except Exception as e:
            diagnostics["artifact_write_error"] = repr(e)

        end_dt = _dt.datetime.now(tz=_dt.timezone.utc)
        finished = end_dt.replace(microsecond=0).strftime(_TIME_FMT)

        return RunResult(
            started_utc=started,
            finished_utc=finished,
            duration_ms=_ms(start_dt, end_dt),
            ok=ok,
            status=status,
            return_code=return_code,
            stdout=stdout_text,
            stderr=stderr_text,
            sandbox_dir=str(sandbox_dir),
            artifacts_dir=str(artifacts_dir),
            policy_applied=policy_applied,
            diagnostics=diagnostics,
        )


# =========================
# CLI
# =========================

def _parse_args(argv: Optional[List[str]]) -> argparse.Namespace:
    import argparse

    p = argparse.ArgumentParser(prog="sandbox_runner", add_help=True)
    p.add_argument("--json", action="store_true", help="Emit JSON result")
    p.add_argument("--timeout", type=int, default=0, help="Override timeout seconds")
    p.add_argument("--cwd", type=str, default="", help="Use provided sandbox cwd (directory)")
    p.add_argument("--artifacts", type=str, default="", help="Artifacts directory")
    p.add_argument("cmd", nargs="+", help="Command to execute (argv...)")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)

    policy = SandboxPolicy()
    if args.timeout and args.timeout > 0:
        policy = dataclasses.replace(policy, timeout_seconds=int(args.timeout))
    if args.cwd:
        policy = dataclasses.replace(policy, cwd_mode="provided")

    runner = SandboxRunner(policy=policy)

    req = RunRequest(
        argv=list(args.cmd),
        cwd=args.cwd or None,
        artifacts_dir=args.artifacts or None,
        label="cli",
        metadata={"invoked_by": "cli"},
    )

    res = runner.run(req)

    if args.json:
        print(json.dumps(dataclasses.asdict(res), ensure_ascii=False, sort_keys=True, indent=2))
    else:
        print(f"status: {res.status}")
        print(f"ok: {res.ok}")
        print(f"return_code: {res.return_code}")
        print(f"duration_ms: {res.duration_ms}")
        print(f"sandbox_dir: {res.sandbox_dir}")
        print(f"artifacts_dir: {res.artifacts_dir}")
        if res.stdout:
            print("stdout:")
            print(res.stdout)
        if res.stderr:
            print("stderr:")
            print(res.stderr)

    # Map status to exit codes
    if res.status == "PASS":
        return 0
    if res.status == "TIMEOUT":
        return 124
    if res.status == "POLICY_DENY":
        return 126
    if res.status == "FAIL":
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
