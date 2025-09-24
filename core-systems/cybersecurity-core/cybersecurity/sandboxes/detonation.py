# cybersecurity-core/cybersecurity/sandboxes/detonation.py
# Industrial-grade artifact detonation orchestrator for dynamic analysis.
#
# Safety defaults:
#   - Network disabled by default.
#   - No-new-privileges, cap_drop=ALL (Docker).
#   - Read-only root FS (Docker), writable /workspace only.
#   - Resource limits: CPU, memory, pids, timeouts.
#   - strace-based behavior trace (optional, off if not available in image).
#   - Host never executes the sample directly (unless Bubblewrap driver is used with strict isolation).
#
# Optional deps:
#   pip install docker yara-python python-magic
#
# Notes:
#   * The module does NOT ship exploit/payload logic. It only executes a provided file in a hardened sandbox.
#   * For Docker driver, use a prebuilt analysis image that already contains 'strace' and any runtimes you need.
#     Example: FROM debian:bookworm-slim && apt-get update && apt-get install -y strace file ca-certificates && apt-get clean
#   * Bubblewrap driver works on Linux with 'bwrap' available and user namespaces enabled.
#
from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import json
import logging
import os
import queue
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

# ---------- Optional third-parties ----------
try:
    import docker  # type: ignore
except Exception:
    docker = None  # pragma: no cover

try:
    import yara  # type: ignore
except Exception:
    yara = None  # pragma: no cover

try:
    import magic  # type: ignore
except Exception:
    magic = None  # pragma: no cover

# ---------- Types & Config ----------

@dataclass(frozen=True)
class SandboxLimits:
    timeout_sec: int = 60
    memory_mb: int = 512
    cpu_quota_percent: int = 100  # ~1 CPU
    pids_limit: int = 256
    stdout_max_bytes: int = 1_000_000
    stderr_max_bytes: int = 1_000_000

@dataclass(frozen=True)
class SandboxNetwork:
    mode: str = "none"  # none | bridge | host
    # Future: sinkhole/pcap settings can be added here.

@dataclass(frozen=True)
class YaraConfig:
    rules_path: Optional[str] = None  # compiled .yar or directory with rules
    scan_generated: bool = False      # scan files created in /workspace after run
    max_match_size: int = 8 * 1024 * 1024

@dataclass(frozen=True)
class DetonationRequest:
    sample_path: str                   # absolute or relative path to a file on host
    args: Sequence[str] = field(default_factory=list)
    env: Mapping[str, str] = field(default_factory=dict)
    working_dir_name: str = "workspace"
    collect_trace: bool = True
    driver: Optional[str] = None       # "docker" | "bubblewrap" | None (auto)
    # Docker specifics:
    docker_image: str = "debian:bookworm-slim"
    docker_user: str = "nobody"        # requires user present in image; otherwise use "65534:65534"
    docker_read_only_root: bool = True
    docker_additional_mounts: Sequence[Tuple[str, str, str]] = field(default_factory=tuple)  # (host, container, mode)
    # Bubblewrap specifics:
    bubblewrap_path: str = "bwrap"
    # Common:
    limits: SandboxLimits = SandboxLimits()
    network: SandboxNetwork = SandboxNetwork()
    yara: YaraConfig = YaraConfig()

@dataclass
class SyscallSummary:
    execve: int = 0
    open: int = 0
    connect: int = 0
    chmod: int = 0
    unlink: int = 0
    write: int = 0
    mmap: int = 0
    ptrace: int = 0
    suspicious: List[str] = field(default_factory=list)

@dataclass
class DetonationResult:
    ok: bool
    error: Optional[str]
    timed_out: bool
    exit_code: Optional[int]
    started_at: float
    finished_at: float
    duration_sec: float
    sample_meta: Dict[str, Any]
    stdout: str
    stderr: str
    driver_used: str
    trace_path: Optional[str]
    syscalls: SyscallSummary
    created_files: List[str]
    yara_matches: List[Dict[str, Any]]

# ---------- Exceptions ----------

class SandboxError(Exception):
    pass

class EnvironmentNotSupported(SandboxError):
    pass

class DriverUnavailable(SandboxError):
    pass

# ---------- Helpers ----------

def _read_truncated(path: Path, max_bytes: int) -> str:
    if not path.exists():
        return ""
    data = path.read_bytes()
    if len(data) > max_bytes:
        return data[:max_bytes].decode(errors="replace")
    return data.decode(errors="replace")

def _hashes(fp: Path) -> Dict[str, str]:
    digests = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256(), "sha512": hashlib.sha512()}
    with fp.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            for d in digests.values():
                d.update(chunk)
    return {k: v.hexdigest() for k, v in digests.items()}

def _file_type(fp: Path) -> str:
    if magic:
        try:
            m = magic.Magic(mime=False)
            return str(m.from_file(str(fp)))
        except Exception:
            pass
    # fallback to 'file' if available
    if shutil.which("file"):
        try:
            out = subprocess.check_output(["file", "-b", str(fp)], stderr=subprocess.DEVNULL, timeout=5)
            return out.decode(errors="replace").strip()
        except Exception:
            pass
    return "unknown"

def _ensure_abs(path: Union[str, Path]) -> Path:
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(str(p))
    return p

def _safe_env(user_env: Mapping[str, str]) -> Dict[str, str]:
    keep = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
    out = dict(keep)
    for k, v in user_env.items():
        if re.fullmatch(r"[A-Z0-9_]{1,64}", k or "") and isinstance(v, str) and len(v) <= 4096:
            out[k] = v
    return out

def _compile_yara(ycfg: YaraConfig, log: logging.Logger) -> Optional[Any]:
    if not (ycfg.rules_path and yara):
        return None
    rp = Path(ycfg.rules_path)
    if not rp.exists():
        log.warning("YARA rules path does not exist: %s", rp)
        return None
    if rp.is_dir():
        sources = {}
        for p in rp.rglob("*.yar"):
            try:
                sources[p.stem] = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                pass
        if not sources:
            log.warning("No YARA .yar files found under %s", rp)
            return None
        return yara.compile(sources=sources)  # type: ignore
    return yara.compile(filepath=str(rp))  # type: ignore

def _scan_yara(rules: Any, paths: Iterable[Path], max_size: int, log: logging.Logger) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    if not rules:
        return results
    for p in paths:
        try:
            if p.is_file() and p.stat().st_size <= max_size:
                matches = rules.match(str(p))  # type: ignore
                for m in matches:
                    results.append({"file": str(p), "rule": m.rule, "tags": list(getattr(m, "tags", []))})
        except Exception as e:
            log.debug("YARA scan error on %s: %s", p, e)
    return results

# ---------- Driver Base ----------

class SandboxDriver:
    name = "base"
    def supported(self) -> bool:
        raise NotImplementedError
    def run(self, req: DetonationRequest, workdir: Path, log: logging.Logger) -> Tuple[int, str, str, Optional[Path], List[Path]]:
        """Execute sample in sandbox and return (exit_code, stdout_text, stderr_text, trace_path, created_files)."""
        raise NotImplementedError

# ---------- Docker Driver ----------

class DockerDriver(SandboxDriver):
    name = "docker"

    def __init__(self):
        self._client = None

    def supported(self) -> bool:
        if docker is None:
            return False
        try:
            self._client = docker.from_env()  # type: ignore
            self._client.ping()  # type: ignore
            return True
        except Exception:
            return False

    def run(self, req: DetonationRequest, workdir: Path, log: logging.Logger) -> Tuple[int, str, str, Optional[Path], List[Path]]:
        if not self._client:
            raise DriverUnavailable("Docker client not available")
        sample = _ensure_abs(req.sample_path)

        # Layout inside container
        c_in = "/sandbox/input"
        c_ws = f"/sandbox/{req.working_dir_name}"
        c_out = "/sandbox/out"
        c_trace = f"{c_out}/trace.log"
        trace_host = workdir / "trace.log"
        stdout_host = workdir / "stdout.txt"
        stderr_host = workdir / "stderr.txt"

        cmd_parts: List[str] = []
        if req.collect_trace:
            cmd_parts.extend(["strace", "-ff", "-tt", "-s", "128", "-o", c_trace])
        # Append executable and args; quote conservatively
        args = " ".join([shlex_quote(str(Path(c_in) / Path(sample.name)))] + [shlex_quote(a) for a in req.args])
        cmd_parts.append(args)
        full_cmd = " ".join(cmd_parts)

        # Volumes
        volumes = {
            str(sample.parent): {"bind": c_in, "mode": "ro"},
            str(workdir): {"bind": c_out, "mode": "rw"},
        }
        # additional mounts
        for host, cont, mode in req.docker_additional_mounts:
            volumes[host] = {"bind": cont, "mode": mode}

        # Resource limits
        mem = f"{req.limits.memory_mb}m"
        nano_cpus = int(1e9 * max(0.1, min(4.0, req.limits.cpu_quota_percent / 100.0)))  # 0.1..4 CPUs
        pids_limit = req.limits.pids_limit

        # Network
        net_mode = None if req.network.mode == "bridge" else req.network.mode
        network_disabled = (req.network.mode == "none")

        # Security opts
        security_opt = ["no-new-privileges:true"]
        cap_drop = ["ALL"]

        # Environment
        env = _safe_env(req.env)

        # Run container
        container = None
        logs_buf = queue.Queue()  # not strictly needed; keeping for future streaming
        try:
            container = self._client.containers.run(  # type: ignore
                image=req.docker_image,
                command=["/bin/sh", "-lc", f"mkdir -p {c_ws} {c_out} && cd {c_ws} && {full_cmd} 1>{c_out}/stdout.txt 2>{c_out}/stderr.txt"],
                user=req.docker_user,
                detach=True,
                working_dir=c_ws,
                volumes=volumes,
                read_only=req.docker_read_only_root,
                mem_limit=mem,
                nano_cpus=nano_cpus,
                pids_limit=pids_limit,
                network_disabled=network_disabled,
                network_mode=net_mode,
                environment=env,
                stdin_open=False,
                tty=False,
                privileged=False,
                cap_drop=cap_drop,
                security_opt=security_opt,
            )
        except Exception as e:
            raise SandboxError(f"Docker run failed: {e}")

        # Timeout guard
        def _killer():
            try:
                container.reload()  # type: ignore
                container.kill()    # type: ignore
            except Exception:
                pass

        timer = threading.Timer(req.limits.timeout_sec, _killer)
        timer.start()
        exit_code = None
        try:
            result = container.wait()  # type: ignore
            exit_code = int(result.get("StatusCode", 1))
        except Exception as e:
            raise SandboxError(f"Docker wait failed: {e}")
        finally:
            timer.cancel()

        # Copy outputs
        try:
            # stdout/stderr
            stdout = (workdir / "stdout.txt").read_text(encoding="utf-8", errors="replace") if (workdir / "stdout.txt").exists() else ""
            stderr = (workdir / "stderr.txt").read_text(encoding="utf-8", errors="replace") if (workdir / "stderr.txt").exists() else ""
        except Exception:
            stdout = ""
            stderr = ""

        trace_path = trace_host if trace_host.exists() else None

        # Collect created files under workspace (on host this is workdir/)
        created_files: List[Path] = []
        for p in workdir.rglob("*"):
            if p.is_file() and p.name not in {"stdout.txt", "stderr.txt", "trace.log"}:
                created_files.append(p)

        # Cleanup container
        with contextlib.suppress(Exception):
            container.remove(force=True)  # type: ignore

        # Truncate outputs
        stdout = stdout[: req.limits.stdout_max_bytes]
        stderr = stderr[: req.limits.stderr_max_bytes]

        return exit_code or 0, stdout, stderr, trace_path, created_files

# ---------- Bubblewrap Driver (Linux) ----------

class BubblewrapDriver(SandboxDriver):
    name = "bubblewrap"

    def supported(self) -> bool:
        return shutil.which("bwrap") is not None

    def run(self, req: DetonationRequest, workdir: Path, log: logging.Logger) -> Tuple[int, str, str, Optional[Path], List[Path]]:
        # This driver executes sample via bubblewrap with network disabled (--unshare-net)
        # and minimal filesystem mounts. Requires Linux user namespaces.
        sample = _ensure_abs(req.sample_path)
        trace_path = workdir / "trace.log"
        stdout_path = workdir / "stdout.txt"
        stderr_path = workdir / "stderr.txt"
        ws = workdir / req.working_dir_name
        ws.mkdir(parents=True, exist_ok=True)

        # Build command
        bwrap = shutil.which(req.bubblewrap_path) or "bwrap"
        mounts = [
            bwrap, "--unshare-net",
            "--die-with-parent",
            "--dev", "/dev",
            "--ro-bind", "/usr", "/usr",
            "--ro-bind", "/bin", "/bin",
            "--ro-bind", "/lib", "/lib",
            "--ro-bind-try", "/lib64", "/lib64",
            "--tmpfs", "/tmp",
            "--bind", str(ws), "/workspace",
            "--ro-bind", str(sample.parent), "/input",
            "--chdir", "/workspace",
        ]
        exec_cmd: List[str] = []
        if req.collect_trace and shutil.which("strace"):
            exec_cmd = ["strace", "-ff", "-tt", "-s", "128", "-o", str(trace_path)]
        exec_cmd += ["/input/" + sample.name] + list(req.args)

        full = mounts + ["--"] + exec_cmd
        env = _safe_env(req.env)

        # Run with timeout and resource limits using 'timeout' and 'prlimit' if available
        wrapper: List[str] = []
        if shutil.which("prlimit"):
            wrapper += ["prlimit", f"--nproc={req.limits.pids_limit}", f"--as={req.limits.memory_mb}M"]
        if shutil.which("timeout"):
            wrapper += ["timeout", f"{req.limits.timeout_sec}s"]

        cmd = wrapper + full

        try:
            with open(stdout_path, "wb") as so, open(stderr_path, "wb") as se:
                proc = subprocess.Popen(cmd, stdout=so, stderr=se, env=env)
                exit_code = proc.wait()
        except Exception as e:
            raise SandboxError(f"Bubblewrap execution failed: {e}")

        # Collect created files
        created_files: List[Path] = []
        for p in ws.rglob("*"):
            if p.is_file():
                created_files.append(p)

        stdout = _read_truncated(stdout_path, req.limits.stdout_max_bytes)
        stderr = _read_truncated(stderr_path, req.limits.stderr_max_bytes)
        return exit_code, stdout, stderr, (trace_path if trace_path.exists() else None), created_files

# ---------- Trace parser ----------

_STRACE_SUSPECT = [
    ("ptrace(", "ptrace"),
    ("LD_PRELOAD", "ld_preload"),
    ("/proc/self/mem", "self_mem"),
    ("mprotect(", "mprotect"),
    ("execve(", "execve"),
    ("connect(", "connect"),
]

def parse_strace(trace_path: Optional[Path]) -> SyscallSummary:
    summ = SyscallSummary()
    if not (trace_path and trace_path.exists()):
        return summ
    # strace -ff creates multiple files like trace.log.pid
    files: List[Path] = []
    if trace_path.is_file():
        files.append(trace_path)
    for p in trace_path.parent.glob(trace_path.name + "*"):
        if p.is_file():
            files.append(p)

    rex_map = {
        "execve": re.compile(r"^\w*\s*execve\("),
        "open": re.compile(r"^\w*\s*(open|openat)\("),
        "connect": re.compile(r"^\w*\s*connect\("),
        "chmod": re.compile(r"^\w*\s*(chmod|fchmod|fchmodat)\("),
        "unlink": re.compile(r"^\w*\s*(unlink|unlinkat)\("),
        "write": re.compile(r"^\w*\s*(write|pwrite|pwrite64)\("),
        "mmap": re.compile(r"^\w*\s*(mmap|mmap2)\("),
        "ptrace": re.compile(r"^\w*\s*ptrace\("),
    }

    suspicious: List[str] = []
    counts = {k: 0 for k in rex_map}
    for fp in files:
        with fp.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                for k, r in rex_map.items():
                    if r.search(line):
                        counts[k] += 1
                for needle, tag in _STRACE_SUSPECT:
                    if needle in line:
                        suspicious.append(tag)

    summ.execve = counts["execve"]
    summ.open = counts["open"]
    summ.connect = counts["connect"]
    summ.chmod = counts["chmod"]
    summ.unlink = counts["unlink"]
    summ.write = counts["write"]
    summ.mmap = counts["mmap"]
    summ.ptrace = counts["ptrace"]
    # unique suspicious
    summ.suspicious = sorted(set(suspicious))
    return summ

# ---------- Manager ----------

class DetonationManager:
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.log = logger or logging.getLogger("detonation")
        self._drivers: Dict[str, SandboxDriver] = {
            "docker": DockerDriver(),
            "bubblewrap": BubblewrapDriver(),
        }

    def _choose_driver(self, req: DetonationRequest) -> SandboxDriver:
        if req.driver:
            drv = self._drivers.get(req.driver)
            if not drv or not drv.supported():
                raise DriverUnavailable(f"Requested driver '{req.driver}' is not available")
            return drv
        # Auto selection: prefer Docker
        for name in ("docker", "bubblewrap"):
            drv = self._drivers[name]
            if drv.supported():
                return drv
        raise EnvironmentNotSupported("Neither Docker nor Bubblewrap is available on this host")

    def detonate(self, req: DetonationRequest) -> DetonationResult:
        start = time.time()
        temp_root = Path(tempfile.mkdtemp(prefix="detonate-")).resolve()
        workdir = temp_root  # used for outputs and workspace mount

        sample = _ensure_abs(req.sample_path)
        sample_meta = {
            "path": str(sample),
            "size": sample.stat().st_size,
            "hashes": _hashes(sample),
            "file_type": _file_type(sample),
        }

        driver = self._choose_driver(req)
        self.log.info("Detonation started with %s", driver.name, extra={"driver": driver.name, "sample": str(sample)})

        compiled_yara = _compile_yara(req.yara, self.log)
        timed_out = False
        exit_code: Optional[int] = None
        stdout = stderr = ""
        trace_path: Optional[Path] = None
        created_files: List[Path] = []
        try:
            exit_code, stdout, stderr, trace_path, created_files = driver.run(req, workdir, self.log)
        except SandboxError as e:
            # Distinguish timeout if we can infer from message
            timed_out = "timeout" in str(e).lower()
            finished = time.time()
            result = DetonationResult(
                ok=False,
                error=str(e),
                timed_out=timed_out,
                exit_code=exit_code,
                started_at=start,
                finished_at=finished,
                duration_sec=round(finished - start, 4),
                sample_meta=sample_meta,
                stdout=stdout,
                stderr=stderr,
                driver_used=driver.name,
                trace_path=str(trace_path) if trace_path else None,
                syscalls=SyscallSummary(),
                created_files=[str(p) for p in created_files],
                yara_matches=[],
            )
            self._cleanup(temp_root)
            return result
        except Exception as e:
            finished = time.time()
            result = DetonationResult(
                ok=False,
                error=f"Unhandled error: {e}",
                timed_out=False,
                exit_code=exit_code,
                started_at=start,
                finished_at=finished,
                duration_sec=round(finished - start, 4),
                sample_meta=sample_meta,
                stdout=stdout,
                stderr=stderr,
                driver_used=driver.name,
                trace_path=str(trace_path) if trace_path else None,
                syscalls=SyscallSummary(),
                created_files=[str(p) for p in created_files],
                yara_matches=[],
            )
            self._cleanup(temp_root)
            return result

        # Parse trace
        syscalls = parse_strace(trace_path)

        # YARA scan
        yara_matches: List[Dict[str, Any]] = []
        try:
            if compiled_yara:
                targets: List[Path] = [sample]
                if req.yara.scan_generated:
                    targets += [p for p in created_files if p.is_file()]
                yara_matches = _scan_yara(compiled_yara, targets, req.yara.max_match_size, self.log)
        except Exception as e:
            self.log.debug("YARA scan failed: %s", e)

        finished = time.time()
        result = DetonationResult(
            ok=True,
            error=None,
            timed_out=False,
            exit_code=exit_code,
            started_at=start,
            finished_at=finished,
            duration_sec=round(finished - start, 4),
            sample_meta=sample_meta,
            stdout=stdout,
            stderr=stderr,
            driver_used=driver.name,
            trace_path=str(trace_path) if trace_path else None,
            syscalls=syscalls,
            created_files=[str(p) for p in created_files],
            yara_matches=yara_matches,
        )

        self._cleanup(temp_root)
        return result

    def _cleanup(self, path: Path) -> None:
        with contextlib.suppress(Exception):
            shutil.rmtree(path, ignore_errors=True)

# ---------- Utilities ----------

def shlex_quote(s: str) -> str:
    # Minimal shlex.quote to avoid importing shlex on stripped installs
    if not s:
        return "''"
    if re.fullmatch(r"[A-Za-z0-9@%_+=:,./-]+", s):
        return s
    return "'" + s.replace("'", "'\"'\"'") + "'"

def result_to_json(res: DetonationResult) -> str:
    d = asdict(res)
    # Ensure deterministic ordering and Unicode safety
    return json.dumps(d, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

# ---------- __main__ (disabled in production imports) ----------

if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    log = logging.getLogger("demo")

    # Example usage (adjust docker_image to one with strace installed):
    req = DetonationRequest(
        sample_path=os.environ.get("SAMPLE", "/bin/true"),
        args=[],
        driver=os.environ.get("DRIVER", None),  # "docker" or "bubblewrap" or None
        docker_image=os.environ.get("IMAGE", "debian:bookworm-slim"),
        collect_trace=True,
        limits=SandboxLimits(timeout_sec=20, memory_mb=256, cpu_quota_percent=100, pids_limit=128),
        network=SandboxNetwork(mode="none"),
        yara=YaraConfig(rules_path=os.environ.get("YARA_RULES", ""), scan_generated=False),
    )

    mgr = DetonationManager(log)
    res = mgr.detonate(req)
    print(result_to_json(res))
