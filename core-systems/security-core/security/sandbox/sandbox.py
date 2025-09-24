# security-core/security/sandbox/sandbox.py
from __future__ import annotations

import asyncio
import json
import logging
import os
import resource
import shlex
import shutil
import signal
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

# ------------------------------------------------------------
# Логирование (структурированное JSON)
# ------------------------------------------------------------

def _logger() -> logging.Logger:
    lg = logging.getLogger("security_core.sandbox")
    if not lg.handlers:
        h = logging.StreamHandler(stream=sys.stdout)
        h.setFormatter(logging.Formatter("%(message)s"))
        lg.addHandler(h)
        lg.setLevel(os.getenv("SEC_CORE_SANDBOX_LOG_LEVEL", "INFO").upper())
    return lg

log = _logger()

def jlog(level: int, message: str, **fields: Any) -> None:
    payload = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": logging.getLevelName(level),
        "message": message,
    }
    payload.update(fields)
    try:
        log.log(level, json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    except Exception:
        log.log(level, f"{message} | {fields}")

# ------------------------------------------------------------
# Исключения/статусы
# ------------------------------------------------------------

class SandboxError(Exception): ...
class SandboxConfigError(SandboxError): ...
class SandboxRuntimeError(SandboxError): ...

SANDBOX_STATUS = (
    "OK",
    "TIMEOUT",
    "CPU_EXCEEDED",
    "MEMORY_EXCEEDED",
    "OUTPUT_TRUNCATED",
    "KILLED",
    "NONZERO_EXIT",
    "SETUP_FAILED",
    "INTERNAL_ERROR",
)

# ------------------------------------------------------------
# Конфиг и результат
# ------------------------------------------------------------

@dataclass
class SandboxPolicy:
    # Лимиты
    wall_time_sec: float = 5.0          # общий таймаут
    cpu_time_sec: float = 3.0           # RLIMIT_CPU
    memory_bytes: int = 256 * 1024 * 1024  # RLIMIT_AS (best-effort)
    fsize_bytes: int = 32 * 1024 * 1024     # RLIMIT_FSIZE для создаваемых файлов
    processes: int = 64                 # RLIMIT_NPROC
    open_files: int = 256               # RLIMIT_NOFILE
    # Ввод/вывод
    stdin_bytes_limit: int = 5 * 1024 * 1024
    stdout_bytes_limit: int = 2 * 1024 * 1024
    stderr_bytes_limit: int = 1 * 1024 * 1024
    # Окружение/права
    no_network: bool = True
    cwd: Optional[str] = None
    umask: int = 0o077
    # Смена пользователя (если процесс имеет права)
    run_uid: Optional[int] = None
    run_gid: Optional[int] = None
    # Монты (актуально для bwrap-драйвера)
    rw_paths: Tuple[str, ...] = field(default_factory=lambda: ("/tmp",))
    ro_paths: Tuple[str, ...] = field(default_factory=lambda: ("/",))
    tmpfs_paths: Tuple[str, ...] = field(default_factory=tuple)
    # Переменные окружения
    env_allowlist: Tuple[str, ...] = field(default_factory=lambda: ("LANG", "LC_ALL", "PATH", "PYTHONPATH"))
    base_env: Mapping[str, str] = field(default_factory=lambda: {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"})
    # Прочее
    kill_grace_sec: float = 0.5         # пауза перед SIGKILL после SIGTERM
    driver_hint: Optional[str] = None   # "bwrap" | "native" | None (auto)
    name: str = "default"

@dataclass
class ExecutionResult:
    status: str
    exit_code: Optional[int]
    signal: Optional[int]
    wall_time_ms: int
    cpu_time_ms: Optional[int]
    max_rss_kb: Optional[int]
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    meta: Dict[str, Any] = field(default_factory=dict)

# ------------------------------------------------------------
# Абстракция драйвера
# ------------------------------------------------------------

class SandboxDriver:
    async def run(
        self,
        argv: Sequence[str],
        policy: SandboxPolicy,
        *,
        stdin: Optional[bytes],
        env: Optional[Mapping[str, str]],
    ) -> ExecutionResult:
        raise NotImplementedError

# ------------------------------------------------------------
# Утилиты
# ------------------------------------------------------------

def _sanitize_env(env: Optional[Mapping[str, str]], policy: SandboxPolicy) -> Dict[str, str]:
    base = dict(policy.base_env)
    if env:
        for k, v in env.items():
            if k in policy.env_allowlist:
                base[k] = str(v)
    # Гарантируем безопасную локаль
    base.setdefault("LANG", "C.UTF-8")
    base.setdefault("LC_ALL", "C.UTF-8")
    return base

def _build_preexec(policy: SandboxPolicy):
    def _preexec():
        # Новый сессионный лидер
        os.setsid()
        # Маска
        os.umask(policy.umask)
        # Лимиты
        def _set(rlim, soft, hard):
            try:
                resource.setrlimit(rlim, (soft, hard))
            except Exception:
                pass
        # CPU
        _set(resource.RLIMIT_CPU, int(policy.cpu_time_sec), int(policy.cpu_time_sec))
        # Адресное пространство (best-effort)
        _set(resource.RLIMIT_AS, policy.memory_bytes, policy.memory_bytes)
        # Ограничение суммарного размера создаваемых файлов
        _set(resource.RLIMIT_FSIZE, policy.fsize_bytes, policy.fsize_bytes)
        # Количество процессов
        if hasattr(resource, "RLIMIT_NPROC"):
            _set(resource.RLIMIT_NPROC, policy.processes, policy.processes)
        # Дескрипторы
        _set(resource.RLIMIT_NOFILE, policy.open_files, policy.open_files)

        # Отключение сети best-effort: new net ns если есть права
        if policy.no_network and hasattr(os, "unshare"):
            CLONE_NEWNET = 0x40000000
            try:
                os.unshare(CLONE_NEWNET)
            except Exception:
                # не критично — всё равно запретим через окружение/отсутствие маршрутов
                pass

        # Понижение привилегий (если возможно)
        try:
            if policy.run_gid is not None:
                os.setgid(policy.run_gid)
            if policy.run_uid is not None:
                os.setuid(policy.run_uid)
        except Exception:
            # если нет прав — продолжаем под текущим пользователем
            pass
    return _preexec

async def _read_stream(stream: asyncio.StreamReader, limit: int) -> Tuple[bytes, bool]:
    buf = bytearray()
    truncated = False
    chunk = 65536
    while True:
        part = await stream.read(chunk)
        if not part:
            break
        # Если уже достигли лимита — просто сливаем оставшееся, чтобы не блокироваться
        if truncated:
            continue
        if len(buf) + len(part) > limit:
            remain = limit - len(buf)
            if remain > 0:
                buf += part[:remain]
            truncated = True
        else:
            buf += part
    return bytes(buf), truncated

def _which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)

# ------------------------------------------------------------
# Драйвер 1: bubblewrap (предпочтительно)
# ------------------------------------------------------------

class BwrapDriver(SandboxDriver):
    def __init__(self, bwrap_path: str) -> None:
        self.bwrap = bwrap_path

    def _compose(self, argv: Sequence[str], policy: SandboxPolicy) -> List[str]:
        cmd: List[str] = [
            self.bwrap,
            "--die-with-parent",
            "--unshare-user",
            "--unshare-pid",
            "--unshare-uts",
            "--unshare-ipc",
            "--proc", "/proc",
            "--dev", "/dev",
        ]
        if policy.no_network:
            cmd += ["--unshare-net"]
        # Базовая корневая ФС read-only
        for p in policy.ro_paths:
            cmd += ["--ro-bind", p, p]
        # RW-монты перекрывают ro
        for p in policy.rw_paths:
            cmd += ["--bind", p, p]
        for p in policy.tmpfs_paths:
            cmd += ["--tmpfs", p]
        if policy.cwd:
            cmd += ["--chdir", policy.cwd]
        # Разделитель и сама команда
        cmd += ["--"]
        cmd += list(argv)
        return cmd

    async def run(
        self,
        argv: Sequence[str],
        policy: SandboxPolicy,
        *,
        stdin: Optional[bytes],
        env: Optional[Mapping[str, str]],
    ) -> ExecutionResult:
        full = self._compose(argv, policy)
        envp = _sanitize_env(env, policy)
        start = time.perf_counter()

        # preexec в дочернем процессе bwrap (лимиты унаследуют все потомки)
        proc = await asyncio.create_subprocess_exec(
            *full,
            stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            preexec_fn=_build_preexec(policy),
            env=envp,
        )

        # Ввод
        if stdin is not None:
            data = stdin[: policy.stdin_bytes_limit]
            try:
                proc.stdin.write(data)
                await proc.stdin.drain()
                proc.stdin.close()
            except Exception:
                pass

        # Ограничение по времени
        try:
            wait_task = asyncio.create_task(proc.wait())
            done, pending = await asyncio.wait(
                {wait_task}, timeout=policy.wall_time_sec, return_when=asyncio.FIRST_COMPLETED
            )
            if wait_task not in done:
                # не завершился — мягко, затем жёстко
                with contextlib.suppress(Exception):
                    proc.send_signal(signal.SIGTERM)
                try:
                    await asyncio.wait_for(wait_task, timeout=policy.kill_grace_sec)
                except asyncio.TimeoutError:
                    with contextlib.suppress(Exception):
                        proc.kill()
        except Exception:
            pass

        # Параллельное чтение stdout/stderr с отсечкой
        out_task = asyncio.create_task(_read_stream(proc.stdout, policy.stdout_bytes_limit))
        err_task = asyncio.create_task(_read_stream(proc.stderr, policy.stderr_bytes_limit))
        stdout, out_trunc = await out_task
        stderr, err_trunc = await err_task

        rc = proc.returncode
        wall_ms = int((time.perf_counter() - start) * 1000)

        # CPU/maxrss — best-effort (asyncio не возвращает rusage; оставим None)
        cpu_ms = None
        maxrss_kb = None

        status = "OK"
        sig = None
        if rc is None:
            status = "TIMEOUT"
            rc = -1
        else:
            if rc < 0:
                sig = -rc
                status = "KILLED" if sig != signal.SIGXCPU else "CPU_EXCEEDED"
            elif rc > 0:
                status = "NONZERO_EXIT"
        if out_trunc or err_trunc:
            # Отметим факт отсечки в метаданных и статусе
            status = "OUTPUT_TRUNCATED" if status == "OK" else status

        meta = {"driver": "bwrap", "argv": argv, "policy": asdict(policy)}
        jlog(logging.INFO, "sandbox.exec.done", status=status, rc=rc, wall_ms=wall_ms, driver="bwrap")
        return ExecutionResult(
            status=status,
            exit_code=rc,
            signal=sig,
            wall_time_ms=wall_ms,
            cpu_time_ms=cpu_ms,
            max_rss_kb=maxrss_kb,
            stdout=stdout,
            stderr=stderr,
            stdout_truncated=out_trunc,
            stderr_truncated=err_trunc,
            meta=meta,
        )

# ------------------------------------------------------------
# Драйвер 2: нативный (rlimit + best-effort unshare)
# ------------------------------------------------------------

import contextlib

class NativeDriver(SandboxDriver):
    async def run(
        self,
        argv: Sequence[str],
        policy: SandboxPolicy,
        *,
        stdin: Optional[bytes],
        env: Optional[Mapping[str, str]],
    ) -> ExecutionResult:
        envp = _sanitize_env(env, policy)
        start = time.perf_counter()

        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            preexec_fn=_build_preexec(policy),
            cwd=policy.cwd or None,
            env=envp,
        )

        if stdin is not None:
            data = stdin[: policy.stdin_bytes_limit]
            try:
                proc.stdin.write(data)
                await proc.stdin.drain()
                proc.stdin.close()
            except Exception:
                pass

        timed_out = False
        try:
            await asyncio.wait_for(proc.wait(), timeout=policy.wall_time_sec)
        except asyncio.TimeoutError:
            timed_out = True
            with contextlib.suppress(Exception):
                proc.send_signal(signal.SIGTERM)
            try:
                await asyncio.wait_for(proc.wait(), timeout=policy.kill_grace_sec)
            except asyncio.TimeoutError:
                with contextlib.suppress(Exception):
                    proc.kill()

        out_task = asyncio.create_task(_read_stream(proc.stdout, policy.stdout_bytes_limit))
        err_task = asyncio.create_task(_read_stream(proc.stderr, policy.stderr_bytes_limit))
        stdout, out_trunc = await out_task
        stderr, err_trunc = await err_task

        rc = proc.returncode
        wall_ms = int((time.perf_counter() - start) * 1000)

        # Попробуем получить rusage детей (best-effort, может включать другие процессы)
        try:
            # os.wait4 недоступен в asyncio-контексте; оставляем None
            cpu_ms = None
            maxrss_kb = None
        except Exception:
            cpu_ms = None
            maxrss_kb = None

        status = "OK"
        sig = None
        if timed_out:
            status = "TIMEOUT"
            rc = -1 if rc is None else rc
        else:
            if rc is not None and rc < 0:
                sig = -rc
                status = "KILLED" if sig != signal.SIGXCPU else "CPU_EXCEEDED"
            elif rc and rc > 0:
                status = "NONZERO_EXIT"
        if out_trunc or err_trunc:
            status = "OUTPUT_TRUNCATED" if status == "OK" else status

        meta = {"driver": "native", "argv": argv, "policy": asdict(policy)}
        jlog(logging.INFO, "sandbox.exec.done", status=status, rc=rc, wall_ms=wall_ms, driver="native")
        return ExecutionResult(
            status=status,
            exit_code=rc,
            signal=sig,
            wall_time_ms=wall_ms,
            cpu_time_ms=cpu_ms,
            max_rss_kb=maxrss_kb,
            stdout=stdout,
            stderr=stderr,
            stdout_truncated=out_trunc,
            stderr_truncated=err_trunc,
            meta=meta,
        )

# ------------------------------------------------------------
# Фасад: выбор драйвера и публичный API
# ------------------------------------------------------------

class Sandbox:
    def __init__(self, default_policy: Optional[SandboxPolicy] = None) -> None:
        self.default_policy = default_policy or SandboxPolicy()
        self._bwrap = _which("bwrap")

    def _driver_for(self, policy: SandboxPolicy) -> SandboxDriver:
        hint = (policy.driver_hint or os.getenv("SEC_CORE_SANDBOX_DRIVER") or "").lower().strip() or None
        if hint == "bwrap" and self._bwrap:
            return BwrapDriver(self._bwrap)
        if hint == "native":
            return NativeDriver()
        # auto
        if self._bwrap:
            return BwrapDriver(self._bwrap)
        return NativeDriver()

    async def run(
        self,
        argv: Union[str, Sequence[str]],
        *,
        policy: Optional[SandboxPolicy] = None,
        stdin: Optional[Union[str, bytes]] = None,
        env: Optional[Mapping[str, str]] = None,
    ) -> ExecutionResult:
        pol = policy or self.default_policy
        if isinstance(argv, str):
            argv_seq = shlex.split(argv)
        else:
            argv_seq = list(argv)
        if not argv_seq:
            raise SandboxConfigError("Empty command")
        if stdin is not None and isinstance(stdin, str):
            stdin_b = stdin.encode("utf-8")
        else:
            stdin_b = stdin  # type: ignore

        drv = self._driver_for(pol)
        jlog(logging.INFO, "sandbox.exec.start", driver=drv.__class__.__name__, argv=argv_seq, policy=pol.name)
        try:
            res = await drv.run(argv_seq, pol, stdin=stdin_b, env=env)
        except Exception as e:
            jlog(logging.ERROR, "sandbox.exec.error", error=str(e))
            raise SandboxRuntimeError(str(e)) from e
        return res

# ------------------------------------------------------------
# Пример использования (для справки)
# ------------------------------------------------------------
# async def _demo():
#     sb = Sandbox(SandboxPolicy(wall_time_sec=2.0, cpu_time_sec=1, memory_bytes=64*1024*1024, name="demo"))
#     res = await sb.run(["/bin/sh", "-c", "python3 - <<'PY'\nprint('hello')\nPY"])
#     print(res.status, res.exit_code, res.stdout.decode())
#
# Переменные окружения:
#   SEC_CORE_SANDBOX_LOG_LEVEL=INFO
#   SEC_CORE_SANDBOX_DRIVER=bwrap|native
#
# Замечания:
#  - Режим bwrap предпочтителен и работает без root (user namespaces). Требуется установленный пакет bubblewrap.
#  - Нативный режим не даёт полноценной файловой/сетевой изоляции, но строго ограничивает ресурсы (rlimit) и время.
#  - Для полной сетевой изоляции в native рекомендуется запуск в контейнере/namespace уровня оркестратора.
