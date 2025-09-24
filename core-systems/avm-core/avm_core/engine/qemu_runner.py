# -*- coding: utf-8 -*-
"""
qemu_runner.py — промышленный QEMU runner для AVM Core.

Особенности:
- Конфигурация VM через dataclass QEMUConfig
- Построение безопасной строки запуска qemu-system-*
- Управление образом диска: qcow2 COW через qemu-img (опционально)
- QMP client для управления VM (graceful shutdown, snapshots, blockdev)
- Healthcheck / watch dog / auto-restart policy
- Clean shutdown with timeout, форсированное убийство при необходимости
- Опциональная интеграция с prometheus_client (если установлен)
- Логирование, исключения и многопоточность для non-blocking операций
- Поддержка user networking и tap (требует предварительной настройки tap/bridge)
- Подготовка окружения, проверка бинарей, валидация путей

Примечание: модуль предполагает наличие системных бинарей `qemu-system-x86_64` и `qemu-img`
в PATH или заданных в конфигурации. Для production рекомендуется запускать
в пространстве с ограничениями cgroups и Seccomp, а также под ограниченным пользователем.
"""
from __future__ import annotations

import json
import logging
import os
import shlex
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Union

# Optional Prometheus integration (non-fatal)
try:
    from prometheus_client import Counter, Gauge
except Exception:  # pragma: no cover - optional dependency
    Counter = None  # type: ignore
    Gauge = None  # type: ignore

logger = logging.getLogger("avm.qemu_runner")

DEFAULT_QEMU_BIN = os.getenv("QEMU_BIN", "qemu-system-x86_64")
DEFAULT_QEMU_IMG = os.getenv("QEMU_IMG", "qemu-img")
DEFAULT_QMP_UNIX_DIR = os.getenv("QMP_DIR", "/var/run/avm/qmp")

# Prometheus metrics (if available)
if Counter is not None:
    VM_STARTS = Counter("avm_vm_starts_total", "Total number of VM start attempts")
    VM_STOPS = Counter("avm_vm_stops_total", "Total number of VM stops")
    VM_CRASHES = Counter("avm_vm_crashes_total", "Total number of VM crashes")
    VM_RUNNING = Gauge("avm_vm_running", "VM running (1/0)", ["vm_id"])
else:
    VM_STARTS = VM_STOPS = VM_CRASHES = VM_RUNNING = None  # type: ignore


class QEMURunnerError(RuntimeError):
    pass


class QMPError(RuntimeError):
    pass


@dataclass
class QEMUConfig:
    vm_id: str
    memory_mb: int = 2048
    cpus: int = 2
    disk_image: Union[str, Path] = ""
    disk_format: str = "qcow2"  # qcow2, raw
    disk_backing_file: Optional[Union[str, Path]] = None  # create COW overlay if set
    enable_kvm: bool = True
    kernel: Optional[Union[str, Path]] = None  # optional kernel for unikernel/minimal
    initrd: Optional[Union[str, Path]] = None
    append_cmdline: Optional[str] = None  # kernel cmdline if kernel set
    qemu_binary: str = DEFAULT_QEMU_BIN
    qemu_img_binary: str = DEFAULT_QEMU_IMG
    qmp_socket_path: Optional[str] = None  # if None, auto-generate under DEFAULT_QMP_UNIX_DIR
    monitor_socket_path: Optional[str] = None  # legacy if needed
    use_user_net: bool = True  # user-mode networking by default (no special privileges)
    nic_model: str = "e1000"
    nic_mac: Optional[str] = None
    tap_interface: Optional[str] = None  # if using tap, name the interface
    extra_args: List[str] = field(default_factory=list)
    stdout_log: Optional[Union[str, Path]] = None  # file to store qemu stdout/stderr
    env: Dict[str, str] = field(default_factory=dict)
    work_dir: Optional[Union[str, Path]] = None
    snapshot_on_start: bool = False
    auto_restart: bool = False
    max_restarts: int = 3
    restart_interval_s: int = 5
    graceful_shutdown_timeout_s: int = 30
    kill_timeout_s: int = 10
    preserve_overlay: bool = False  # keep COW overlay after shutdown
    uid: Optional[int] = None  # optional user to drop privileges before exec
    gid: Optional[int] = None


# ---------- QMP client (unix domain socket) ----------
class QMPClient:
    """
    Minimal QMP client for unix socket communication with QEMU.
    Uses text-based JSON messages terminated by newline.
    """

    def __init__(self, socket_path: str, timeout: float = 5.0):
        self.socket_path = socket_path
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._greeting: Optional[dict] = None
        self._lock = threading.RLock()

    def connect(self) -> None:
        logger.debug("QMP: connecting to %s", self.socket_path)
        if self._sock:
            return
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect(self.socket_path)
            # read greeting (single JSON)
            data = self._recv_one(s)
            try:
                self._greeting = json.loads(data)
            except Exception:
                raise QMPError("Invalid QMP greeting")
            self._sock = s
            logger.debug("QMP: connected, greeting=%s", self._greeting)
        except Exception as e:
            s.close()
            raise QMPError(f"Failed to connect to QMP socket {self.socket_path}: {e}")

    def close(self) -> None:
        with self._lock:
            if self._sock:
                try:
                    self._sock.close()
                finally:
                    self._sock = None

    def _recv_one(self, sock: socket.socket) -> str:
        # Read until newline (qemu qmp sends full JSON + newline)
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk.decode("utf-8", errors="ignore"))
            if "\n" in chunks[-1]:
                break
        return "".join(chunks).strip()

    def command(self, cmd: str, args: Optional[dict] = None, timeout: Optional[float] = None) -> dict:
        with self._lock:
            if not self._sock:
                self.connect()
            payload = {"execute": cmd}
            if args:
                payload["arguments"] = args
            msg = json.dumps(payload) + "\n"
            assert self._sock is not None
            self._sock.sendall(msg.encode("utf-8"))
            # read reply
            prev_timeout = self._sock.gettimeout()
            self._sock.settimeout(timeout or self.timeout)
            try:
                data = self._recv_one(self._sock)
                if not data:
                    raise QMPError("No response from QMP")
                resp = json.loads(data)
                if "error" in resp:
                    raise QMPError(resp["error"])
                return resp
            finally:
                self._sock.settimeout(prev_timeout)


# ---------- Utilities ----------
def _check_binary(path: str) -> str:
    """Return resolved path to binary or raise."""
    resolved = shutil.which(path)
    if not resolved:
        raise QEMURunnerError(f"Required binary not found in PATH: {path}")
    return resolved


def _ensure_dir(path: Union[str, Path], mode: int = 0o700) -> None:
    p = Path(path)
    if not p.exists():
        p.mkdir(parents=True, mode=mode, exist_ok=True)
    else:
        # tighten permissions
        try:
            p.chmod(mode)
        except Exception:
            pass


def _mk_overlay(base_image: str, runner_tmpdir: str, qemu_img_bin: str) -> Tuple[str, str]:
    """
    Create a qcow2 overlay on top of base_image in runner_tmpdir.
    Returns (overlay_path, backing_file_path)
    """
    base = Path(base_image)
    if not base.exists():
        raise QEMURunnerError(f"Base image not found: {base_image}")
    overlay = Path(runner_tmpdir) / f"{base.stem}-{int(time.time())}-overlay.qcow2"
    cmd = [qemu_img_bin, "create", "-f", "qcow2", "-b", str(base), str(overlay)]
    logger.debug("Creating overlay: %s", " ".join(shlex.quote(x) for x in cmd))
    subprocess.run(cmd, check=True)
    return str(overlay), str(base)


# ---------- QEMU Runner ----------
class QEMURunner:
    def __init__(self, cfg: QEMUConfig):
        self.cfg = cfg
        self._validate_and_prepare()
        self._proc: Optional[subprocess.Popen] = None
        self._qmp: Optional[QMPClient] = None
        self._tmpdir: Optional[str] = None
        self._overlay_path: Optional[str] = None
        self._restart_count = 0
        self._lock = threading.RLock()

    def _validate_and_prepare(self) -> None:
        # Validate qemu binaries
        self.cfg.qemu_binary = _check_binary(self.cfg.qemu_binary)
        self.cfg.qemu_img_binary = _check_binary(self.cfg.qemu_img_binary)
        # Validate disk
        if not self.cfg.disk_image:
            raise QEMURunnerError("disk_image is required")
        disk_path = Path(self.cfg.disk_image)
        if not disk_path.exists() and not self.cfg.disk_backing_file:
            raise QEMURunnerError(f"disk_image does not exist: {self.cfg.disk_image}")
        # Prepare qmp socket dir
        qmp_dir = Path(self.cfg.qmp_socket_path or DEFAULT_QMP_UNIX_DIR).parent
        _ensure_dir(qmp_dir, mode=0o700)
        # Prepare working dir
        if self.cfg.work_dir:
            _ensure_dir(self.cfg.work_dir, mode=0o750)
        else:
            # create ephemeral tmpdir per instance
            self._tmpdir = tempfile.mkdtemp(prefix=f"avm-qemu-{self.cfg.vm_id}-")
            self.cfg.work_dir = self._tmpdir
        # ensure stdout_log parent dir exists
        if self.cfg.stdout_log:
            _ensure_dir(Path(self.cfg.stdout_log).parent, mode=0o750)

    def _build_qmp_socket_path(self) -> str:
        if self.cfg.qmp_socket_path:
            return str(self.cfg.qmp_socket_path)
        base_dir = Path(DEFAULT_QMP_UNIX_DIR)
        _ensure_dir(base_dir, mode=0o700)
        sock = base_dir / f"{self.cfg.vm_id}.qmp"
        return str(sock)

    def _build_command(self) -> List[str]:
        cmd: List[str] = [self.cfg.qemu_binary]
        # Basic machine
        if self.cfg.enable_kvm:
            cmd += ["-enable-kvm"]
        cmd += ["-m", str(self.cfg.memory_mb)]
        cmd += ["-smp", str(self.cfg.cpus)]
        # qmp socket
        qmp_path = self._build_qmp_socket_path()
        cmd += ["-qmp", f"unix:{qmp_path},server,nowait"]
        # monitor (extra)
        if self.cfg.monitor_socket_path:
            cmd += ["-monitor", f"unix:{self.cfg.monitor_socket_path},server,nowait"]
        # disk
        # prefer blockdev style to avoid fd leaks
        disk_drive_id = "drive0"
        if self._overlay_path:
            drive_file = self._overlay_path
            backing = True
        else:
            drive_file = str(self.cfg.disk_image)
            backing = False
        # blockdev node with file and format
        cmd += [
            "-drive",
            f"file={drive_file},format={self.cfg.disk_format},if=virtio,cache=none,aio=threads,discard=unmap"
        ]
        # networking
        if self.cfg.use_user_net:
            cmd += ["-netdev", f"user,id=net0,hostfwd=tcp::0-:22"]  # hostfwd 0 means dynamic ephemeral host port
            cmd += ["-device", f"{self.cfg.nic_model},netdev=net0"]
        else:
            # TAP requires external setup and privileges
            if not self.cfg.tap_interface:
                raise QEMURunnerError("tap_interface must be specified when use_user_net=False")
            cmd += ["-netdev", f"tap,id=net0,ifname={self.cfg.tap_interface},script=no,downscript=no"]
            cmd += ["-device", f"{self.cfg.nic_model},netdev=net0,mac={self.cfg.nic_mac or ''}"]
        # kernel/initrd (optional)
        if self.cfg.kernel:
            cmd += ["-kernel", str(self.cfg.kernel)]
            if self.cfg.initrd:
                cmd += ["-initrd", str(self.cfg.initrd)]
            if self.cfg.append_cmdline:
                cmd += ["-append", shlex.quote(self.cfg.append_cmdline)]
        # disable graphical output
        cmd += ["-nographic"]
        # disable default monitor unless explicitly requested
        cmd += ["-nodefaults"]
        # extra args
        if self.cfg.extra_args:
            cmd += list(self.cfg.extra_args)
        # pidfile
        pidfile = Path(self.cfg.work_dir) / f"{self.cfg.vm_id}.pid"
        cmd += ["-pidfile", str(pidfile)]
        logger.debug("Built qemu command: %s", cmd)
        return cmd

    def _prepare_overlay_if_needed(self) -> None:
        if self.cfg.disk_backing_file and not self._overlay_path:
            # create overlay pointing to disk_backing_file if provided
            try:
                overlay, backing = _mk_overlay(self.cfg.disk_backing_file, str(self.cfg.work_dir), self.cfg.qemu_img_binary)
                self._overlay_path = overlay
                # Use overlay as drive
                logger.info("Created overlay %s -> backing %s", overlay, backing)
            except Exception as e:
                raise QEMURunnerError(f"Failed to create overlay: {e}")

    def start(self) -> None:
        """Start the VM process. Non-blocking."""
        with self._lock:
            if self._proc and self._proc.poll() is None:
                raise QEMURunnerError("VM already running")
            self._prepare_overlay_if_needed()
            cmd = self._build_command()
            stdout = subprocess.DEVNULL
            stderr = subprocess.STDOUT
            if self.cfg.stdout_log:
                f = open(self.cfg.stdout_log, "a+", buffering=1)
                stdout = f
                stderr = f
            env = os.environ.copy()
            env.update(self.cfg.env or {})
            # Optionally drop privileges via setuid/setgid in preexec_fn
            preexec_fn = None
            if self.cfg.uid is not None or self.cfg.gid is not None:
                def _drop_priv():
                    try:
                        if self.cfg.gid is not None:
                            os.setgid(self.cfg.gid)
                        if self.cfg.uid is not None:
                            os.setuid(self.cfg.uid)
                    except Exception as e:
                        logger.exception("Failed to drop privileges: %s", e)
                        raise
                preexec_fn = _drop_priv
            try:
                logger.info("Starting VM %s", self.cfg.vm_id)
                if VM_STARTS:
                    VM_STARTS.inc()
                self._proc = subprocess.Popen(cmd, stdout=stdout, stderr=stderr, cwd=str(self.cfg.work_dir), env=env, preexec_fn=preexec_fn)
            except Exception as exc:
                raise QEMURunnerError(f"Failed to start qemu: {exc}")
            # create qmp client lazily on health check or user request
            self._restart_count = 0
            # start monitor thread for process exit
            threading.Thread(target=self._watch_process, daemon=True).start()
            self._set_prometheus_running(1)

    def _watch_process(self) -> None:
        """Background watcher: restarts according to policy or records crashes."""
        proc = self._proc
        if not proc:
            return
        ret = proc.wait()
        logger.warning("VM %s exited with code %s", self.cfg.vm_id, ret)
        self._set_prometheus_running(0)
        if VM_CRASHES:
            VM_CRASHES.inc()
        with self._lock:
            self._proc = None
            if self.cfg.auto_restart and self._restart_count < self.cfg.max_restarts:
                self._restart_count += 1
                logger.info("Auto-restarting VM %s (attempt %d)", self.cfg.vm_id, self._restart_count)
                time.sleep(self.cfg.restart_interval_s)
                try:
                    self.start()
                except Exception:
                    logger.exception("Auto-restart failed for VM %s", self.cfg.vm_id)
            else:
                logger.info("Not restarting VM %s (auto_restart=%s, restart_count=%d)", self.cfg.vm_id, self.cfg.auto_restart, self._restart_count)

    def _set_prometheus_running(self, val: int) -> None:
        if VM_RUNNING:
            try:
                VM_RUNNING.labels(vm_id=self.cfg.vm_id).set(val)
            except Exception:
                pass

    def stop(self, force: bool = False) -> None:
        """
        Attempt graceful shutdown via QMP system_powerdown; after timeout, kill.
        If force=True, directly kill.
        """
        with self._lock:
            if not self._proc:
                logger.info("VM %s is not running", self.cfg.vm_id)
                return
            proc = self._proc
            if force:
                logger.info("Force-killing VM %s", self.cfg.vm_id)
                proc.kill()
                proc.wait(timeout=self.cfg.kill_timeout_s)
                VM_STOPS and VM_STOPS.inc()
                self._set_prometheus_running(0)
                return
            # Try graceful via QMP
            try:
                qmp = self.qmp_client()
                try:
                    qmp.command("system_powerdown")
                except QMPError:
                    logger.debug("QMP powerdown failed, falling back to SIGTERM")
                    proc.terminate()
                # wait for graceful_shutdown_timeout_s
                try:
                    proc.wait(timeout=self.cfg.graceful_shutdown_timeout_s)
                except subprocess.TimeoutExpired:
                    logger.warning("Graceful shutdown timeout, sending SIGTERM")
                    proc.terminate()
                    try:
                        proc.wait(timeout=self.cfg.kill_timeout_s)
                    except subprocess.TimeoutExpired:
                        logger.warning("SIGTERM failed, killing process")
                        proc.kill()
                        proc.wait()
            except Exception as e:
                logger.exception("Shutdown via QMP failed: %s", e)
                # fallback to signal
                try:
                    proc.terminate()
                    proc.wait(timeout=self.cfg.kill_timeout_s)
                except Exception:
                    proc.kill()
                    proc.wait()
            finally:
                VM_STOPS and VM_STOPS.inc()
                self._set_prometheus_running(0)
                # cleanup overlay if requested
                if self._overlay_path and not self.cfg.preserve_overlay:
                    try:
                        os.remove(self._overlay_path)
                        logger.info("Removed overlay %s", self._overlay_path)
                    except Exception:
                        logger.debug("Failed to remove overlay %s", self._overlay_path)

    def qmp_client(self) -> QMPClient:
        with self._lock:
            if self._qmp:
                return self._qmp
            sock = self._build_qmp_socket_path()
            q = QMPClient(sock, timeout=5.0)
            q.connect()
            self._qmp = q
            return q

    def create_snapshot(self, name: str) -> dict:
        """Create internal snapshot via QMP."""
        q = self.qmp_client()
        try:
            # create blockdev snapshot (simple approach)
            res = q.command("savevm", {"name": name})
            logger.info("Created snapshot %s: %s", name, res)
            return res
        except QMPError as e:
            raise QEMURunnerError(f"Failed to create snapshot: {e}")

    def revert_snapshot(self, name: str) -> dict:
        q = self.qmp_client()
        try:
            res = q.command("loadvm", {"name": name})
            logger.info("Reverted to snapshot %s", name)
            return res
        except QMPError as e:
            raise QEMURunnerError(f"Failed to revert snapshot: {e}")

    def execute_qmp(self, cmd: str, args: Optional[dict] = None, timeout: float = 5.0) -> dict:
        q = self.qmp_client()
        return q.command(cmd, args, timeout)

    def health_check(self) -> Tuple[bool, str]:
        """Check VM process and QMP responsiveness."""
        with self._lock:
            proc = self._proc
            if not proc:
                return False, "not-running"
            if proc.poll() is not None:
                return False, f"exited:{proc.returncode}"
            # check qmp
            try:
                q = self.qmp_client()
                resp = q.command("query-status")
                state = resp.get("return", {}).get("status", "unknown")
                return True, state
            except Exception as e:
                logger.debug("QMP healthcheck failed: %s", e)
                return False, "qmp-unreachable"

    def info(self) -> dict:
        with self._lock:
            info = {
                "vm_id": self.cfg.vm_id,
                "pid": self._proc.pid if self._proc else None,
                "running": self._proc is not None and self._proc.poll() is None,
                "overlay": self._overlay_path,
                "tmpdir": self._tmpdir,
            }
            # attempt qmp status
            try:
                ok, state = self.health_check()
                info["qemu_state"] = state
            except Exception:
                info["qemu_state"] = "unknown"
            return info

    def cleanup(self) -> None:
        """Cleanup temporary artifacts (tmpdir) if created."""
        with self._lock:
            if self._tmpdir and Path(self._tmpdir).exists():
                try:
                    shutil.rmtree(self._tmpdir)
                except Exception:
                    logger.exception("Failed to cleanup tmpdir %s", self._tmpdir)

    # Context manager semantics
    def __enter__(self) -> "QEMURunner":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            self.stop(force=False)
        finally:
            self.cleanup()
