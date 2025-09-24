# path: core-systems/avm_core/vpn/vpn_client.py
# -*- coding: utf-8 -*-
"""
Industrial-grade VPN client orchestrator for WireGuard and OpenVPN.

Key features:
- Async process control via asyncio.subprocess (no external deps).
- Backends: WireGuard (wg-quick) and OpenVPN (management-less default, optional mgmt).
- Secure runtime with 0700/0600 perms for configs/keys, ephemeral files, dry-run for tests.
- Health checks: interface state, peer handshake age (WG), ping route, DNS probe, log-driven readiness (OVPN).
- Pluggable CommandRunner for unit tests; strict timeouts and structured error taxonomy.
- JSON-structured logging with correlation_id for traceability; signal-safe shutdown.
- Kubernetes/sidecar friendly: optional runtime_dir under /tmp or mounted volume.
- Safe defaults; no secret leakage in logs. Python 3.11+.

Note:
- Root privileges typically required to bring interfaces up/down. In non-root or dry-run mode the client will
  prepare configs and simulate commands for CI/tests.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import signal
import stat
import sys
import tempfile
import time
from dataclasses import dataclass, field, asdict
from enum import Enum, StrEnum, auto
from pathlib import Path
from typing import Any, Awaitable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

__all__ = [
    "VPNType",
    "VPNError",
    "ConfigError",
    "ProcessError",
    "HealthCheckFailed",
    "VPNConfig",
    "WGPeer",
    "OVPNRemote",
    "HealthConfig",
    "TunnelState",
    "CommandRunner",
    "VPNClient",
]

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

_LOG = logging.getLogger("avm_core.vpn")
if not _LOG.handlers:
    _LOG.setLevel(logging.INFO)
    _h = logging.StreamHandler(sys.stdout)
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    _LOG.addHandler(_h)


def _log_json(level: int, event: str, **fields: Any) -> None:
    """Emit JSON-structured log line."""
    try:
        payload = {"event": event, **fields}
        _LOG.log(level, json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    except Exception:
        # Fallback to plain text if JSON serialization fails.
        _LOG.log(level, f"{event} {fields}")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class VPNError(RuntimeError):
    pass


class ConfigError(VPNError):
    pass


class ProcessError(VPNError):
    pass


class HealthCheckFailed(VPNError):
    pass


# ---------------------------------------------------------------------------
# Types / Config
# ---------------------------------------------------------------------------

class VPNType(StrEnum):
    WIREGUARD = "wireguard"
    OPENVPN = "openvpn"


@dataclass(slots=True)
class WGPeer:
    public_key: str
    allowed_ips: list[str]
    endpoint: Optional[str] = None           # host:port
    persistent_keepalive: Optional[int] = 25  # seconds, 0 disables
    psk: Optional[str] = None                 # optional preshared key (base64)


@dataclass(slots=True)
class OVPNRemote:
    host: str
    port: int = 1194
    proto: str = "udp"  # udp/tcp
    sni: Optional[str] = None


@dataclass(slots=True)
class HealthConfig:
    check_interval_s: float = 5.0
    # ICMP ping is not implemented in pure Python stdlib; use system ping for route probe.
    route_probe: Optional[str] = None  # e.g., "1.1.1.1" checked via /bin/ping
    dns_probe: Optional[str] = None    # DNS name to resolve through tunnel (uses `getent hosts`)
    startup_grace_s: float = 10.0
    handshake_max_age_s: int = 180  # WG: last handshake within this window considered healthy
    ovpn_ready_regex: str = r"Initialization Sequence Completed"


@dataclass(slots=True)
class VPNConfig:
    name: str
    vpn_type: VPNType
    interface: str
    runtime_dir: Path
    dry_run: bool = False

    # WireGuard specifics
    wg_private_key: Optional[str] = None          # base64, 32 bytes
    wg_address: Optional[str] = None              # e.g., "10.6.0.2/32"
    wg_listen_port: Optional[int] = None          # optional when acting as server, typically None for client
    wg_mtu: Optional[int] = 1420
    wg_dns: Optional[list[str]] = None            # e.g., ["10.6.0.1"]
    wg_peers: list[WGPeer] = field(default_factory=list)

    # OpenVPN specifics
    ovpn_remotes: list[OVPNRemote] = field(default_factory=list)
    ovpn_ca: Optional[str] = None                 # PEM
    ovpn_cert: Optional[str] = None               # PEM
    ovpn_key: Optional[str] = None                # PEM
    ovpn_tls_auth_key: Optional[str] = None       # inline ta.key (optional)
    ovpn_cipher: str = "AES-256-GCM"
    ovpn_auth: str = "SHA256"
    ovpn_verify_x509_name: Optional[str] = None   # server CN
    ovpn_extra: list[str] = field(default_factory=lambda: ["remote-cert-tls server", "nobind", "persist-key", "persist-tun"])

    # Common
    up_timeout_s: float = 30.0
    stop_timeout_s: float = 20.0
    env: dict[str, str] = field(default_factory=dict)
    health: HealthConfig = field(default_factory=HealthConfig)
    correlation_id: str = field(default_factory=lambda: secrets.token_hex(8))

    def validate(self) -> None:
        if not self.name or not re.fullmatch(r"[a-zA-Z0-9_\-\.]{1,64}", self.name):
            raise ConfigError("Invalid VPN name")
        if not re.fullmatch(r"[a-zA-Z0-9_\-\.]{1,32}", self.interface):
            raise ConfigError("Invalid interface name")
        if self.vpn_type == VPNType.WIREGUARD:
            if not self.wg_private_key or not self.wg_address or not self.wg_peers:
                raise ConfigError("WireGuard requires wg_private_key, wg_address, wg_peers")
            # Validate IP/CIDR
            try:
                ipaddress.ip_network(self.wg_address, strict=False)
            except Exception as e:
                raise ConfigError(f"Invalid wg_address: {e}") from e
        elif self.vpn_type == VPNType.OPENVPN:
            if not self.ovpn_remotes:
                raise ConfigError("OpenVPN requires at least one remote")
            if not (self.ovpn_ca and self.ovpn_cert and self.ovpn_key):
                raise ConfigError("OpenVPN requires CA, cert and key")
            for r in self.ovpn_remotes:
                if r.proto not in ("udp", "tcp"):
                    raise ConfigError("OpenVPN remote proto must be udp or tcp")
        else:
            raise ConfigError("Unsupported VPN type")

        self.runtime_dir = Path(self.runtime_dir).absolute()

    # Sensitive dump for debugging without keys
    def safe_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # redact secrets
        for k in ("wg_private_key", "ovpn_key", "ovpn_cert", "ovpn_ca", "ovpn_tls_auth_key"):
            if d.get(k):
                d[k] = f"<redacted:{k}>"
        return d


@dataclass(slots=True)
class TunnelState:
    interface: str
    up: bool
    backend: VPNType
    since: float | None = None
    last_handshake: float | None = None  # WG only, monotonic seconds since handshake
    bytes_in: int | None = None
    bytes_out: int | None = None
    details: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Command runner abstraction
# ---------------------------------------------------------------------------

class CommandRunner:
    """Async command runner with timeouts, capturing, and dry-run support."""
    def __init__(self, dry_run: bool = False):
        self._dry = dry_run

    async def run(
        self,
        *argv: str,
        timeout: float | None = None,
        env: Optional[Mapping[str, str]] = None,
        cwd: Optional[Path] = None,
        capture: bool = True,
    ) -> tuple[int, str, str]:
        if self._dry:
            _log_json(logging.DEBUG, "cmd.dry_run", argv=list(argv), cwd=str(cwd) if cwd else None)
            return (0, "", "")
        if shutil.which(argv[0]) is None:
            raise ProcessError(f"Executable not found: {argv[0]}")
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE if capture else asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE if capture else asyncio.subprocess.DEVNULL,
            env={**os.environ, **(env or {})},
            cwd=str(cwd) if cwd else None,
        )
        try:
            if timeout:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            else:
                stdout, stderr = await proc.communicate()
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            raise ProcessError(f"Timeout running: {' '.join(argv)}")
        out = stdout.decode(errors="ignore") if stdout else ""
        err = stderr.decode(errors="ignore") if stderr else ""
        return (proc.returncode, out, err)

    async def spawn(
        self,
        *argv: str,
        env: Optional[Mapping[str, str]] = None,
        cwd: Optional[Path] = None,
        stdout_cb: Optional[callable[[str], None]] = None,
        stderr_cb: Optional[callable[[str], None]] = None,
    ) -> asyncio.subprocess.Process:
        if self._dry:
            _log_json(logging.DEBUG, "spawn.dry_run", argv=list(argv), cwd=str(cwd) if cwd else None)
            # Spawn a dummy process that exits quickly
            return await asyncio.create_subprocess_exec("bash", "-lc", "sleep 3600")
        if shutil.which(argv[0]) is None:
            raise ProcessError(f"Executable not found: {argv[0]}")
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, **(env or {})},
            cwd=str(cwd) if cwd else None,
        )

        async def _pump(reader: asyncio.StreamReader, cb: Optional[callable[[str], None]], tag: str):
            if not reader or not cb:
                return
            while True:
                line = await reader.readline()
                if not line:
                    break
                try:
                    cb(line.decode(errors="ignore").rstrip("\n"))
                except Exception:
                    _log_json(logging.WARNING, "log.pump_error", tag=tag)

        # Background tasks to drain pipes to avoid deadlocks
        asyncio.create_task(_pump(proc.stdout, stdout_cb, "stdout"))
        asyncio.create_task(_pump(proc.stderr, stderr_cb, "stderr"))
        return proc


# ---------------------------------------------------------------------------
# Backend base
# ---------------------------------------------------------------------------

class _Backend:
    def __init__(self, cfg: VPNConfig, runner: CommandRunner):
        self.cfg = cfg
        self.runner = runner
        self._started_monotonic: float | None = None
        self._proc: asyncio.subprocess.Process | None = None
        self._iface_up_event = asyncio.Event()
        self._stdout_buf: list[str] = []
        self._stderr_buf: list[str] = []

    @property
    def started_at(self) -> float | None:
        return self._started_monotonic

    def _ensure_runtime(self) -> Path:
        self.cfg.runtime_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.cfg.runtime_dir, 0o700)
        return self.cfg.runtime_dir

    def _write_secure(self, rel: str, content: str, mode: int = 0o600) -> Path:
        root = self._ensure_runtime()
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(path, mode)
        return path

    def _on_stdout(self, line: str) -> None:
        if len(self._stdout_buf) < 1000:
            self._stdout_buf.append(line)
        _log_json(logging.DEBUG, "backend.stdout", line=line, cid=self.cfg.correlation_id)

    def _on_stderr(self, line: str) -> None:
        if len(self._stderr_buf) < 1000:
            self._stderr_buf.append(line)
        _log_json(logging.DEBUG, "backend.stderr", line=line, cid=self.cfg.correlation_id)

    async def start(self) -> None:
        raise NotImplementedError

    async def stop(self, timeout: float) -> None:
        raise NotImplementedError

    async def status(self) -> TunnelState:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# WireGuard backend
# ---------------------------------------------------------------------------

class _WireGuardBackend(_Backend):
    _WG_QUICK = "wg-quick"
    _WG = "wg"
    _IP = "ip"

    def _build_wg_quick_conf(self) -> Path:
        c = self.cfg
        iface = c.interface
        peers: list[str] = []
        for p in c.wg_peers:
            peer_lines = [f"[Peer]", f"PublicKey = {p.public_key}", f"AllowedIPs = {', '.join(p.allowed_ips)}"]
            if p.endpoint:
                peer_lines.append(f"Endpoint = {p.endpoint}")
            if p.persistent_keepalive:
                peer_lines.append(f"PersistentKeepalive = {max(0, int(p.persistent_keepalive))}")
            if p.psk:
                peer_lines.append(f"PresharedKey = {p.psk}")
            peers.append("\n".join(peer_lines))

        iface_lines = [
            "[Interface]",
            f"Address = {c.wg_address}",
            f"PrivateKey = {c.wg_private_key}",
        ]
        if c.wg_listen_port:
            iface_lines.append(f"ListenPort = {c.wg_listen_port}")
        if c.wg_mtu:
            iface_lines.append(f"MTU = {c.wg_mtu}")
        if c.wg_dns:
            iface_lines.append(f"DNS = {', '.join(c.wg_dns)}")

        conf = "\n\n".join(["\n".join(iface_lines), *peers]) + "\n"
        # Important: do not log secrets
        return self._write_secure(f"wg/{iface}.conf", conf, 0o600)

    async def start(self) -> None:
        c = self.cfg
        conf_path = self._build_wg_quick_conf()
        _log_json(logging.INFO, "wg.start", iface=c.interface, conf=str(conf_path), cid=c.correlation_id)

        # wg-quick up <conf or iface>
        # Using file path form ensures exact config is used.
        argv = [self._WG_QUICK, "up", str(conf_path)]
        self._proc = await self.runner.spawn(
            *argv, stdout_cb=self._on_stdout, stderr_cb=self._on_stderr
        )
        # wg-quick exits almost immediately; consider interface up after 'ip link show'
        self._started_monotonic = time.monotonic()

        # Wait for interface present
        await self._wait_iface_up(c.up_timeout_s)
        self._iface_up_event.set()
        _log_json(logging.INFO, "wg.up", iface=c.interface, cid=c.correlation_id)

    async def _wait_iface_up(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            rc, out, _ = await self.runner.run(self._IP, "link", "show", self.cfg.interface, timeout=3.0)
            if rc == 0 and self.cfg.interface in out:
                return
            await asyncio.sleep(0.5)
        raise ProcessError(f"Interface {self.cfg.interface} not up within timeout")

    async def stop(self, timeout: float) -> None:
        c = self.cfg
        conf_path = self.cfg.runtime_dir / f"wg/{c.interface}.conf"
        argv = [self._WG_QUICK, "down", str(conf_path)]
        _log_json(logging.INFO, "wg.stop", iface=c.interface, cid=c.correlation_id)
        # wg-quick down
        rc, out, err = await self.runner.run(*argv, timeout=timeout)
        if rc != 0:
            raise ProcessError(f"wg-quick down failed: {err or out}")

    async def status(self) -> TunnelState:
        c = self.cfg
        # wg show <iface>
        rc, out, err = await self.runner.run(self._WG, "show", c.interface, timeout=3.0)
        if rc != 0:
            return TunnelState(interface=c.interface, up=False, backend=VPNType.WIREGUARD, details={"err": err})
        details: dict[str, Any] = {}
        last_handshake: float | None = None
        bytes_in: int | None = None
        bytes_out: int | None = None

        # Parse human-readable output robustly
        # patterns: "latest handshake: 1 minute, 30 seconds ago" or "latest handshake: 0 seconds ago"
        hs_re = re.compile(r"latest handshake:\s+(?:(\d+)\s+(\w+))?.*?ago", re.IGNORECASE)
        rx_re = re.compile(r"transfer:\s+([\d\.]+\s+\w+)\s+received,\s+([\d\.]+\s+\w+)\s+sent", re.IGNORECASE)

        blocks = out.split("\n\n")
        for b in blocks:
            for line in b.splitlines():
                m = hs_re.search(line)
                if m:
                    # cannot reliably convert "minute/seconds" to exact seconds; leave None and expose text
                    details["last_handshake_line"] = line.strip()
                m2 = rx_re.search(line)
                if m2:
                    details["transfer_line"] = line.strip()
        # wg show <iface> dump gives raw counters
        rc2, out2, _ = await self.runner.run(self._WG, "show", c.interface, "dump", timeout=3.0)
        if rc2 == 0:
            # Format: interface, private_key, public_key, listen_port, fwmark
            # peer: public_key, preshared_key, endpoint, allowed_ips, latest_handshake, transfer_rx, transfer_tx, persistent_keepalive
            lines = [ln for ln in out2.splitlines() if ln.strip()]
            for ln in lines[1:]:
                parts = ln.split("\t")
                if len(parts) >= 8:
                    try:
                        hs = int(parts[4])
                        last_handshake = None if hs == 0 else float(hs)
                        bytes_in = int(parts[5])
                        bytes_out = int(parts[6])
                        break
                    except Exception:
                        pass
        up = True
        return TunnelState(
            interface=c.interface,
            up=up,
            backend=VPNType.WIREGUARD,
            since=self.started_at,
            last_handshake=last_handshake,
            bytes_in=bytes_in,
            bytes_out=bytes_out,
            details=details,
        )


# ---------------------------------------------------------------------------
# OpenVPN backend
# ---------------------------------------------------------------------------

class _OpenVPNBackend(_Backend):
    _OPENVPN = "openvpn"

    def _build_ovpn_conf(self) -> Path:
        c = self.cfg
        lines: list[str] = [
            "client",
            "dev tun",
            "resolv-retry infinite",
            "remote-random",
            f"cipher {c.ovpn_cipher}",
            f"auth {c.ovpn_auth}",
            "verb 3",
        ]
        for r in c.ovpn_remotes:
            lines.append(f"remote {r.host} {r.port} {r.proto}")
            if r.sni:
                lines.append(f"server-poll-timeout 10")
                lines.append(f"tls-server")  # compatibility fallback
                lines.append(f"remote-cert-tls server")

        for extra in c.ovpn_extra:
            if extra.strip():
                lines.append(extra.strip())

        # Inline certs/keys to avoid external files
        def inline(tag: str, content: str) -> list[str]:
            return [f"<{tag}>", content.strip(), f"</{tag}>"]

        if c.ovpn_ca:
            lines += inline("ca", c.ovpn_ca)
        if c.ovpn_cert:
            lines += inline("cert", c.ovpn_cert)
        if c.ovpn_key:
            lines += inline("key", c.ovpn_key)
        if c.ovpn_tls_auth_key:
            lines += inline("tls-auth", c.ovpn_tls_auth_key)

        path = self._write_secure("openvpn/client.ovpn", "\n".join(lines) + "\n", 0o600)
        return path

    async def start(self) -> None:
        c = self.cfg
        conf = self._build_ovpn_conf()
        _log_json(logging.INFO, "ovpn.start", conf=str(conf), cid=c.correlation_id)

        args = [
            self._OPENVPN,
            "--config",
            str(conf),
            "--pull",
            "--script-security",
            "2",
            "--up-delay",
        ]
        # Spawn in foreground to parse readiness
        ready_re = re.compile(c.health.ovpn_ready_regex)
        ready_evt = asyncio.Event()

        def on_stdout(line: str) -> None:
            self._on_stdout(line)
            if ready_re.search(line):
                ready_evt.set()

        self._proc = await self.runner.spawn(*args, stdout_cb=on_stdout, stderr_cb=self._on_stderr)
        self._started_monotonic = time.monotonic()

        # Wait for readiness line
        try:
            await asyncio.wait_for(ready_evt.wait(), timeout=c.up_timeout_s)
        except asyncio.TimeoutError:
            raise ProcessError("OpenVPN did not become ready within timeout")
        self._iface_up_event.set()
        _log_json(logging.INFO, "ovpn.up", cid=c.correlation_id)

    async def stop(self, timeout: float) -> None:
        if not self._proc:
            return
        _log_json(logging.INFO, "ovpn.stop.begin")
        with contextlib.suppress(ProcessLookupError):
            self._proc.send_signal(signal.SIGTERM)
        try:
            await asyncio.wait_for(self._proc.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                self._proc.kill()
        _log_json(logging.INFO, "ovpn.stop.done")

    async def status(self) -> TunnelState:
        # OpenVPN lacks a simple status without management; we approximate via process state
        up = self._iface_up_event.is_set()
        return TunnelState(
            interface=self.cfg.interface,
            up=up,
            backend=VPNType.OPENVPN,
            since=self.started_at,
            details={
                "stdout_tail": self._stdout_buf[-5:],
                "stderr_tail": self._stderr_buf[-5:],
            },
        )


# ---------------------------------------------------------------------------
# VPN Client Orchestrator
# ---------------------------------------------------------------------------

class VPNClient:
    """Unified orchestrator over VPN backends with health checks and lifecycle control."""

    def __init__(self, cfg: VPNConfig, runner: Optional[CommandRunner] = None):
        cfg.validate()
        self.cfg = cfg
        self.runner = runner or CommandRunner(dry_run=cfg.dry_run)
        self._backend: _Backend = self._mk_backend(cfg)
        self._hc_task: asyncio.Task[None] | None = None
        self._healthy: bool = False
        self._closed: bool = False

    def _mk_backend(self, cfg: VPNConfig) -> _Backend:
        if cfg.vpn_type == VPNType.WIREGUARD:
            self._require_bins(["wg-quick", "wg", "ip"])
            return _WireGuardBackend(cfg, self.runner)
        elif cfg.vpn_type == VPNType.OPENVPN:
            self._require_bins(["openvpn"])
            return _OpenVPNBackend(cfg, self.runner)
        raise ConfigError("Unsupported VPN type")

    def _require_bins(self, bins: Iterable[str]) -> None:
        if self.cfg.dry_run:
            return
        missing = [b for b in bins if shutil.which(b) is None]
        if missing:
            raise ProcessError(f"Required binaries not found: {', '.join(missing)}")

    # ---------------------------
    # Lifecycle
    # ---------------------------

    async def start(self) -> None:
        _log_json(logging.INFO, "vpn.start", cfg=self.cfg.safe_dict(), cid=self.cfg.correlation_id)
        self._ensure_runtime_perms()
        await self._backend.start()
        # Start health loop
        self._hc_task = asyncio.create_task(self._health_loop())
        _log_json(logging.INFO, "vpn.started", cid=self.cfg.correlation_id)

    async def stop(self) -> None:
        if self._closed:
            return
        self._closed = True
        _log_json(logging.INFO, "vpn.stop", cid=self.cfg.correlation_id)
        if self._hc_task:
            self._hc_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._hc_task
        await self._backend.stop(timeout=self.cfg.stop_timeout_s)
        _log_json(logging.INFO, "vpn.stopped", cid=self.cfg.correlation_id)

    async def restart(self) -> None:
        await self.stop()
        # Prepare fresh backend (new process, fresh state)
        self._backend = self._mk_backend(self.cfg)
        self._closed = False
        await self.start()

    # ---------------------------
    # Status / Health
    # ---------------------------

    async def status(self) -> TunnelState:
        s = await self._backend.status()
        s.details["healthy"] = self._healthy
        return s

    def healthy(self) -> bool:
        return self._healthy

    async def _health_loop(self) -> None:
        # Grace period
        await asyncio.sleep(self.cfg.health.startup_grace_s)
        while True:
            try:
                ok = await self._probe_once()
                self._healthy = ok
                _log_json(logging.INFO, "vpn.health", ok=ok, cid=self.cfg.correlation_id)
            except Exception as e:
                _log_json(logging.WARNING, "vpn.health.error", err=str(e), cid=self.cfg.correlation_id)
                self._healthy = False
            await asyncio.sleep(self.cfg.health.check_interval_s)

    async def _probe_once(self) -> bool:
        st = await self._backend.status()
        if not st.up:
            return False
        # Backend-specific checks
        if self.cfg.vpn_type == VPNType.WIREGUARD:
            if st.last_handshake is not None:
                # wg dump returns monotonic-like epoch seconds; treat 0 as unknown
                max_age = self.cfg.health.handshake_max_age_s
                # Accept if we have any handshake timestamp > 0 within window
                # If last_handshake is epoch seconds (sec since 1970), approximate with now
                now = int(time.time())
                age = max(0, now - int(st.last_handshake))
                if age > max_age:
                    return False

        # Optional route probe via ping
        if self.cfg.health.route_probe and not self.cfg.dry_run:
            dest = self.cfg.health.route_probe
            rc, _, _ = await self.runner.run(
                "ping", "-c", "1", "-W", "2", dest, timeout=4.0
            )
            if rc != 0:
                return False

        # Optional DNS probe (through system resolver)
        if self.cfg.health.dns_probe and not self.cfg.dry_run:
            name = self.cfg.health.dns_probe
            rc, out, _ = await self.runner.run("getent", "hosts", name, timeout=3.0)
            if rc != 0 or not out.strip():
                return False

        return True

    # ---------------------------
    # Utilities
    # ---------------------------

    def _ensure_runtime_perms(self) -> None:
        d = self.cfg.runtime_dir
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)
        # Hardening: ensure world/other cannot read
        st_mode = d.stat().st_mode
        if st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            os.chmod(d, 0o700)

    # Key rotation (WireGuard only) – hot apply via `wg set`
    async def rotate_wg_private_key(self, new_private_key: str) -> None:
        if self.cfg.vpn_type != VPNType.WIREGUARD:
            raise ConfigError("WireGuard only")
        self.cfg.wg_private_key = new_private_key
        if self.cfg.dry_run:
            _log_json(logging.INFO, "wg.rotate_key.dry", cid=self.cfg.correlation_id)
            return
        rc, out, err = await self.runner.run("wg", "set", self.cfg.interface, "private-key", "/dev/stdin",
                                             timeout=3.0, env=None)
        # The above won't pass stdin with current abstraction; apply via temp file
        tmp = self.cfg.runtime_dir / "wg/new.key"
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(new_private_key + "\n", encoding="utf-8")
        os.chmod(tmp, 0o600)
        rc, out, err = await self.runner.run("wg", "set", self.cfg.interface, "private-key", str(tmp), timeout=3.0)
        if rc != 0:
            raise ProcessError(f"wg set private-key failed: {err or out}")
        _log_json(logging.INFO, "wg.rotate_key.ok", cid=self.cfg.correlation_id)

    # Change WG peer endpoint on the fly
    async def set_wg_peer_endpoint(self, peer_public_key: str, endpoint: str) -> None:
        if self.cfg.vpn_type != VPNType.WIREGUARD:
            raise ConfigError("WireGuard only")
        if self.cfg.dry_run:
            _log_json(logging.INFO, "wg.set_peer_endpoint.dry", peer=peer_public_key, endpoint=endpoint)
            return
        rc, out, err = await self.runner.run(
            "wg", "set", self.cfg.interface, "peer", peer_public_key, "endpoint", endpoint, timeout=3.0
        )
        if rc != 0:
            raise ProcessError(f"wg set peer endpoint failed: {err or out}")
        _log_json(logging.INFO, "wg.set_peer_endpoint.ok", peer=peer_public_key, endpoint=endpoint)

    # Safe serialization for observability
    def to_dict(self) -> dict[str, Any]:
        return self.cfg.safe_dict()
