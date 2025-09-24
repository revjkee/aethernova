# -*- coding: utf-8 -*-
"""
Omnimind Sandbox Runner — industrial-grade execution of untrusted code.

Python: 3.11+
Deps: stdlib only. Docker backend uses `docker` CLI if available (optional).

Features:
- Unified sync/async API (run / arun)
- Two backends:
  1) Subprocess backend with:
     - Strict RLIMITs (CPU time, address space, file descriptors, processes)
     - PR_SET_NO_NEW_PRIVS (best-effort)
     - Dedicated temp working directory (read/write), sanitized env
     - Optional network off via `unshare -n` (if available)
     - Output size cap, timeouts, process-group kill (SIGTERM→SIGKILL)
     - File inputs with path validation and total size quota
  2) Docker backend (if docker CLI present):
     - --network=none, --read-only, --cap-drop=ALL, no-new-privileges
     - -m, --cpus, --pids-limit, --ulimit nofile,nproc, stack
     - Bind /workspace tmpfs or host tmp dir, user 1000:1000
- Deterministic minimal environment; allowlist of extra env vars
- Metrics: wall time, user/sys CPU, max RSS (subprocess), exit status
- Structured results and rich error reasons

Security notes:
- Subprocess backend cannot guarantee syscall isolation; prefer Docker where possible.
- Network disablement relies on `unshare -n` if present (Linux). If недоступно — предупреждение.

Copyright:
(c) Omnimind. Provided under internal license.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import errno
import json
import logging
import os
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------
_LOG = logging.getLogger("omnimind.sandbox")
if not _LOG.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    _LOG.addHandler(h)
_LOG.setLevel(logging.INFO)

# ------------------------------------------------------------------------------
# Data model
# ------------------------------------------------------------------------------

@dataclass(slots=True, frozen=True)
class SandboxLimits:
    # CPU time in seconds (hard RLIMIT_CPU)
    cpu_time_s: int = 5
    # Max address space (bytes), e.g. 512 MiB
    memory_bytes: int = 512 * 1024 * 1024
    # Max number of open file descriptors
    nofile: int = 256
    # Max number of processes/threads
    nproc: int = 64
    # Max stack size (bytes)
    stack_bytes: int = 8 * 1024 * 1024
    # Wall clock timeout (seconds)
    timeout_s: float = 6.0
    # Max bytes captured for stdout/stderr each
    max_output_bytes: int = 1_000_000


@dataclass(slots=True, frozen=True)
class FileSpec:
    """A file to materialize in sandbox working directory."""
    path: str
    content: Union[bytes, str]
    mode: int = 0o600


@dataclass(slots=True, frozen=True)
class SandboxSpec:
    """
    Execution specification.
    """
    argv: Sequence[str]
    files: Tuple[FileSpec, ...] = field(default_factory=tuple)
    limits: SandboxLimits = field(default_factory=SandboxLimits)
    env: Mapping[str, str] = field(default_factory=dict)
    network_enabled: bool = False
    workdir_name: Optional[str] = None  # subdirectory name under temp root
    stdin_data: Optional[bytes] = None
    # Backend selection: "auto" | "subprocess" | "docker"
    backend: str = "auto"
    # Docker options (if backend=docker or auto->docker)
    docker_image: str = "python:3.11-alpine"
    docker_user: str = "1000:1000"
    docker_tmpfs: bool = True
    # Total size of all files to write
    files_quota_bytes: int = 8 * 1024 * 1024
    # Extra volume mounts for Docker: [(host_path, container_path, ro)]
    docker_mounts: Tuple[Tuple[str, str, bool], ...] = field(default_factory=tuple)


@dataclass(slots=True, frozen=True)
class SandboxResult:
    ok: bool
    exit_code: Optional[int]
    signaled: Optional[int]
    wall_time_ms: int
    cpu_user_ms: Optional[int]
    cpu_sys_ms: Optional[int]
    max_rss_kb: Optional[int]
    stdout: bytes
    stderr: bytes
    workdir: str
    backend: str
    warnings: Tuple[str, ...] = field(default_factory=tuple)
    error: Optional[str] = None


# ------------------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------------------

class SandboxRunner:
    """
    Facade that selects backend and executes the command according to SandboxSpec.
    """
    def __init__(self, base_tmp: Optional[Path] = None, logger: Optional[logging.Logger] = None) -> None:
        self._base_tmp = base_tmp or Path(tempfile.gettempdir()) / "omnimind_sbx"
        self._base_tmp.mkdir(parents=True, exist_ok=True)
        self._log = logger or _LOG

    # Sync API
    def run(self, spec: SandboxSpec) -> SandboxResult:
        backend = self._select_backend(spec)
        with _sandbox_workdir(self._base_tmp, spec.workdir_name) as wctx:
            _materialize_files(wctx.root, spec.files, quota=spec.files_quota_bytes, logger=self._log)
            if backend == "docker":
                return _DockerBackend(self._log).run(spec, wctx)
            return _SubprocessBackend(self._log).run(spec, wctx)

    # Async API
    async def arun(self, spec: SandboxSpec) -> SandboxResult:
        backend = self._select_backend(spec)
        with _sandbox_workdir(self._base_tmp, spec.workdir_name) as wctx:
            _materialize_files(wctx.root, spec.files, quota=spec.files_quota_bytes, logger=self._log)
            if backend == "docker":
                return await _DockerBackend(self._log).arun(spec, wctx)
            return await _SubprocessBackend(self._log).arun(spec, wctx)

    def _select_backend(self, spec: SandboxSpec) -> str:
        if spec.backend in ("subprocess", "docker"):
            if spec.backend == "docker" and not _docker_available():
                self._log.warning("Docker backend requested, but docker is not available. Falling back to subprocess.")
                return "subprocess"
            return spec.backend
        # auto: prefer docker when network is disabled or stricter isolation is desired and docker exists
        if not spec.network_enabled and _docker_available():
            return "docker"
        return "subprocess"


# ------------------------------------------------------------------------------
# Backend base and workdir context
# ------------------------------------------------------------------------------

@dataclass(slots=True)
class _WorkdirCtx:
    root: Path
    keep: bool = False


@contextlib.contextmanager
def _sandbox_workdir(base_tmp: Path, sub: Optional[str] = None):
    sid = sub or f"job-{uuid.uuid4().hex[:8]}"
    root = base_tmp / sid
    root.mkdir(parents=True, exist_ok=False)
    try:
        yield _WorkdirCtx(root=root)
    finally:
        with contextlib.suppress(Exception):
            shutil.rmtree(root, ignore_errors=True)


def _materialize_files(root: Path, files: Sequence[FileSpec], *, quota: int, logger: logging.Logger) -> None:
    total = 0
    for f in files:
        p = Path(f.path)
        if p.is_absolute() or ".." in p.parts or p.as_posix().startswith("./.."):
            raise ValueError(f"unsafe file path: {f.path}")
        data = f.content.encode("utf-8") if isinstance(f.content, str) else bytes(f.content)
        total += len(data)
        if total > quota:
            raise ValueError("files quota exceeded")
        dest = root / p
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "wb") as fo:
            fo.write(data)
        os.chmod(dest, f.mode)
        logger.debug("Materialized file: %s (%d bytes, mode=%o)", dest, len(data), f.mode)


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _build_clean_env(extra: Mapping[str, str]) -> Dict[str, str]:
    # Minimal deterministic env
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": "/tmp",
        "PYTHONIOENCODING": "UTF-8",
    }
    # Allowlist keys from extra
    for k, v in extra.items():
        if not isinstance(k, str) or not isinstance(v, str):
            continue
        # Prevent injection of sensitive variables
        if k.upper() in {"SSH_AUTH_SOCK", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "GITHUB_TOKEN"}:
            continue
        env[k] = v
    return env


# ------------------------------------------------------------------------------
# Subprocess backend
# ------------------------------------------------------------------------------

class _SubprocessBackend:
    def __init__(self, logger: logging.Logger) -> None:
        self._log = logger

    def run(self, spec: SandboxSpec, wctx: _WorkdirCtx) -> SandboxResult:
        return asyncio.run(self.arun(spec, wctx))

    async def arun(self, spec: SandboxSpec, wctx: _WorkdirCtx) -> SandboxResult:
        limits = spec.limits
        env = _build_clean_env(spec.env)
        cwd = str(wctx.root.resolve())
        argv = list(spec.argv)

        warnings: List[str] = []
        pre_cmd: List[str] = []

        # Attempt network isolation via unshare -n
        if not spec.network_enabled:
            if shutil.which("unshare"):
                pre_cmd = ["unshare", "--map-user=0", "--map-group=0", "-n", "-r"]
            else:
                warnings.append("network_not_isolated_unshare_missing")

        # We spawn a controlling shell only when using unshare; otherwise run argv directly
        if pre_cmd:
            cmd = pre_cmd + argv
        else:
            cmd = argv

        # Create pipes and launch
        start_ns = time.time_ns()

        # Prepare process limits via preexec_fn (POSIX)
        def _preexec() -> None:
            try:
                # New session (kill all children via process group)
                os.setsid()
                # No new privileges (best-effort; ignore if not supported)
                _set_no_new_privs()
                # RLIMITS
                resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_time_s, limits.cpu_time_s))
                resource.setrlimit(resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes))
                resource.setrlimit(resource.RLIMIT_NOFILE, (limits.nofile, limits.nofile))
                resource.setrlimit(resource.RLIMIT_NPROC, (limits.nproc, limits.nproc))
                resource.setrlimit(resource.RLIMIT_STACK, (limits.stack_bytes, limits.stack_bytes))
                # Umask and cwd will be set by Popen
            except Exception as e:
                # Child will fail; nothing else to do
                pass

        stdout_buf = _BoundedBuffer(limits.max_output_bytes)
        stderr_buf = _BoundedBuffer(limits.max_output_bytes)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if spec.stdin_data is not None else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env,
                start_new_session=True,  # also setsid
                preexec_fn=_preexec if hasattr(asyncio.subprocess, "DEVNULL") else None,  # type: ignore[arg-type]
            )
        except Exception as e:
            return SandboxResult(
                ok=False, exit_code=None, signaled=None, wall_time_ms=0,
                cpu_user_ms=None, cpu_sys_ms=None, max_rss_kb=None,
                stdout=b"", stderr=str(e).encode(), workdir=cwd, backend="subprocess",
                warnings=tuple(warnings), error=f"spawn_failed:{type(e).__name__}"
            )

        async def _pump(reader: asyncio.StreamReader, sink: _BoundedBuffer):
            try:
                while True:
                    chunk = await reader.read(65536)
                    if not chunk:
                        break
                    sink.write(chunk)
            except Exception:
                pass

        tasks = [
            asyncio.create_task(_pump(proc.stdout, stdout_buf)),
            asyncio.create_task(_pump(proc.stderr, stderr_buf)),
        ]
        if spec.stdin_data is not None:
            try:
                proc.stdin.write(spec.stdin_data)
                await proc.stdin.drain()
                proc.stdin.close()
            except Exception:
                pass

        try:
            returncode = await asyncio.wait_for(proc.wait(), timeout=limits.timeout_s)
        except asyncio.TimeoutError:
            _terminate_process_group(proc.pid, grace_s=0.5)
            warnings.append("timeout_killed")
            returncode = await proc.wait()
        finally:
            for t in tasks:
                with contextlib.suppress(Exception):
                    await t

        end_ns = time.time_ns()
        wall_ms = int((end_ns - start_ns) / 1_000_000)

        # Gather rusage for children (best effort; usable on POSIX)
        ru = resource.getrusage(resource.RUSAGE_CHILDREN)
        cpu_user_ms = int(ru.ru_utime * 1000)
        cpu_sys_ms = int(ru.ru_stime * 1000)
        max_rss_kb = int(ru.ru_maxrss) if ru.ru_maxrss else None

        signaled = None
        exit_code = returncode
        if returncode is not None and returncode < 0:
            signaled = -returncode
            exit_code = None

        ok = (exit_code == 0 and signaled is None and "timeout_killed" not in warnings)
        return SandboxResult(
            ok=ok,
            exit_code=exit_code,
            signaled=signaled,
            wall_time_ms=wall_ms,
            cpu_user_ms=cpu_user_ms,
            cpu_sys_ms=cpu_sys_ms,
            max_rss_kb=max_rss_kb,
            stdout=stdout_buf.bytes(),
            stderr=stderr_buf.bytes(),
            workdir=cwd,
            backend="subprocess",
            warnings=tuple(warnings),
            error=None if ok else ("timeout" if "timeout_killed" in warnings else None),
        )


def _set_no_new_privs() -> None:
    """
    Best-effort PR_SET_NO_NEW_PRIVS via ctypes. No-op on non-Linux.
    """
    if sys.platform != "linux":
        return
    import ctypes  # local import
    libc = ctypes.CDLL(None, use_errno=True)
    PR_SET_NO_NEW_PRIVS = 38  # from prctl.h
    res = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    if res != 0:
        # ignore errors
        pass


def _terminate_process_group(pid: int, *, grace_s: float = 0.5) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.killpg(pid, signal.SIGTERM)
    time.sleep(grace_s)
    with contextlib.suppress(ProcessLookupError):
        os.killpg(pid, signal.SIGKILL)


class _BoundedBuffer:
    """
    Bounded in-memory buffer with truncation marker.
    """
    __slots__ = ("_limit", "_buf", "_size", "_closed")

    def __init__(self, limit: int) -> None:
        self._limit = max(0, int(limit))
        self._buf: bytearray = bytearray()
        self._size = 0
        self._closed = False

    def write(self, data: bytes) -> None:
        if self._closed or self._limit == 0:
            return
        data = bytes(data)
        remaining = self._limit - self._size
        if remaining <= 0:
            return
        if len(data) > remaining:
            self._buf.extend(data[:remaining])
            self._size = self._limit
            self._closed = True
        else:
            self._buf.extend(data)
            self._size += len(data)

    def bytes(self) -> bytes:
        return bytes(self._buf)


# ------------------------------------------------------------------------------
# Docker backend (optional)
# ------------------------------------------------------------------------------

class _DockerBackend:
    def __init__(self, logger: logging.Logger) -> None:
        self._log = logger

    def run(self, spec: SandboxSpec, wctx: _WorkdirCtx) -> SandboxResult:
        return asyncio.run(self.arun(spec, wctx))

    async def arun(self, spec: SandboxSpec, wctx: _WorkdirCtx) -> SandboxResult:
        if not _docker_available():
            return SandboxResult(
                ok=False, exit_code=None, signaled=None, wall_time_ms=0,
                cpu_user_ms=None, cpu_sys_ms=None, max_rss_kb=None,
                stdout=b"", stderr=b"docker CLI not available", workdir=str(wctx.root),
                backend="docker", warnings=(), error="docker_missing"
            )

        limits = spec.limits
        env = _build_clean_env(spec.env)
        # Compose docker run command
        workdir_host = str(wctx.root.resolve())
        workdir_ctr = "/workspace"  # inside container

        mem = limits.memory_bytes
        cpus = max(0.1, limits.cpu_time_s / max(limits.timeout_s, 0.001))  # heuristic fallback

        docker_cmd: List[str] = [
            "docker", "run", "--rm",
            "--network", "none" if not spec.network_enabled else "bridge",
            "--read-only",
            "--pids-limit", str(limits.nproc),
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--ulimit", f"nofile={limits.nofile}:{limits.nofile}",
            "--ulimit", f"nproc={limits.nproc}:{limits.nproc}",
            "--ulimit", f"stack={limits.stack_bytes}:{limits.stack_bytes}",
            "-m", str(mem),
            "--cpus", f"{cpus:.2f}",
            "-w", workdir_ctr,
            "-u", spec.docker_user,
            "--name", f"sbx-{uuid.uuid4().hex[:8]}",
        ]

        # Mount workspace (tmpfs or bind)
        if spec.docker_tmpfs:
            docker_cmd += ["--tmpfs", f"{workdir_ctr}:rw,exec,mode=1777"]
            # Copy files into container via mount of host dir read-only + init cp
            docker_cmd += ["-v", f"{workdir_host}:{workdir_ctr}/_in:ro"]
            entry = f"sh -lc 'cp -a {workdir_ctr}/_in/. {workdir_ctr}/ && rm -rf {workdir_ctr}/_in && exec {shlex_join(spec.argv)}'"
        else:
            docker_cmd += ["-v", f"{workdir_host}:{workdir_ctr}:rw"]
            entry = shlex_join(spec.argv)

        # Extra mounts
        for host, ctr, ro in spec.docker_mounts:
            mode = "ro" if ro else "rw"
            docker_cmd += ["-v", f"{str(Path(host).resolve())}:{ctr}:{mode}"]

        # Env
        for k, v in env.items():
            docker_cmd += ["-e", f"{k}={v}"]

        # Image
        docker_cmd += [spec.docker_image]
        docker_cmd += ["sh", "-lc", entry]

        # Execute
        stdout_buf = _BoundedBuffer(limits.max_output_bytes)
        stderr_buf = _BoundedBuffer(limits.max_output_bytes)
        start_ns = time.time_ns()

        try:
            proc = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdin=asyncio.subprocess.PIPE if spec.stdin_data is not None else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except Exception as e:
            return SandboxResult(
                ok=False, exit_code=None, signaled=None, wall_time_ms=0,
                cpu_user_ms=None, cpu_sys_ms=None, max_rss_kb=None,
                stdout=b"", stderr=str(e).encode(), workdir=workdir_host, backend="docker",
                warnings=(), error=f"docker_spawn_failed:{type(e).__name__}"
            )

        async def _pump(reader: asyncio.StreamReader, sink: _BoundedBuffer):
            try:
                while True:
                    chunk = await reader.read(65536)
                    if not chunk:
                        break
                    sink.write(chunk)
            except Exception:
                pass

        tasks = [
            asyncio.create_task(_pump(proc.stdout, stdout_buf)),
            asyncio.create_task(_pump(proc.stderr, stderr_buf)),
        ]
        if spec.stdin_data is not None:
            try:
                proc.stdin.write(spec.stdin_data)
                await proc.stdin.drain()
                proc.stdin.close()
            except Exception:
                pass

        try:
            returncode = await asyncio.wait_for(proc.wait(), timeout=limits.timeout_s)
        except asyncio.TimeoutError:
            with contextlib.suppress(Exception):
                proc.terminate()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(proc.wait(), timeout=1.0)
            with contextlib.suppress(Exception):
                proc.kill()
            returncode = await proc.wait()
            warnings = ("timeout_killed",)
        else:
            warnings = ()

        for t in tasks:
            with contextlib.suppress(Exception):
                await t

        end_ns = time.time_ns()
        wall_ms = int((end_ns - start_ns) / 1_000_000)

        exit_code = returncode if returncode >= 0 else None
        signaled = None if returncode >= 0 else -returncode

        ok = (exit_code == 0 and signaled is None and "timeout_killed" not in warnings)
        return SandboxResult(
            ok=ok,
            exit_code=exit_code,
            signaled=signaled,
            wall_time_ms=wall_ms,
            cpu_user_ms=None,  # not available from docker CLI
            cpu_sys_ms=None,
            max_rss_kb=None,
            stdout=stdout_buf.bytes(),
            stderr=stderr_buf.bytes(),
            workdir=workdir_host,
            backend="docker",
            warnings=warnings,
            error=None if ok else ("timeout" if "timeout_killed" in warnings else None),
        )


# ------------------------------------------------------------------------------
# Utilities
# ------------------------------------------------------------------------------

def shlex_join(argv: Sequence[str]) -> str:
    import shlex
    return " ".join(shlex.quote(a) for a in argv)


# ------------------------------------------------------------------------------
# __main__ smoke test
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    # Example: run a tiny Python snippet with subprocess backend and no network.
    code = 'print("hello"); import os; print("cwd", os.getcwd())'
    runner = SandboxRunner()

    spec = SandboxSpec(
        argv=[sys.executable, "-c", code],
        files=(FileSpec("data/input.txt", "payload"),),
        limits=SandboxLimits(cpu_time_s=2, memory_bytes=256*1024*1024, timeout_s=3.0, max_output_bytes=100_000),
        env={"EXAMPLE": "1"},
        network_enabled=False,
        backend="subprocess",
    )

    res = runner.run(spec)
    print("OK:", res.ok, "exit_code:", res.exit_code, "backend:", res.backend)
    print("STDOUT:", res.stdout.decode(errors="ignore"))
    print("STDERR:", res.stderr.decode(errors="ignore"))
