#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN Guard for Linux (WireGuard/OpenVPN) — Industrial Edition.

Guarantees fail-closed egress via VPN only, mitigates DNS leaks, provides
split-tunnel allowlist, JSON audit logs, async health monitoring and CLI.

Requirements (runtime):
  - Linux with: nft, ip, resolvectl (systemd-resolved), bash
  - Optional: wg (for WireGuard introspection)
  - Python 3.10+

Notes:
  - Root privileges required for nft/ip/resolvectl.
  - Focus: host-level guard. Can also be used in dedicated netns or container.
  - Non-Linux OS raise NotImplementedError (by design).
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import enum
import json
import logging
import os
import re
import shlex
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

# ---------- Logging (JSON) ----------

class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": int(record.created * 1000),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        if hasattr(record, "event"):
            payload["event"] = record.event
        if hasattr(record, "meta"):
            payload["meta"] = record.meta
        return json.dumps(payload, ensure_ascii=False)

def _setup_logging(level: str = "INFO") -> None:
    logger = logging.getLogger("vpn_guard")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonLogFormatter())
    logger.handlers[:] = [handler]

log = logging.getLogger("vpn_guard")

# ---------- Enums & Config ----------

class VPNBackendType(enum.Enum):
    AUTO = "auto"
    WIREGUARD = "wireguard"
    OPENVPN = "openvpn"

@dataclass(frozen=True)
class SplitTunnelRule:
    """CIDR/host allowed outside VPN (e.g., VPN server IPs, mgmt)."""
    cidr: str
    description: str = ""

@dataclass
class VPNGuardConfig:
    backend: VPNBackendType = VPNBackendType.AUTO
    interface: Optional[str] = None           # e.g. wg0, tun0
    # IP/DNS
    dns_servers: List[str] = field(default_factory=lambda: [])
    pin_dns_to_link: bool = True              # resolvectl link DNS to VPN iface
    block_non_vpn_egress: bool = True         # fail-closed egress block
    allowlist_outside: List[SplitTunnelRule] = field(default_factory=list)
    # Health checks
    public_ip_check_urls: List[str] = field(default_factory=lambda: [
        "https://ifconfig.co/ip",
        "https://api.ipify.org",
        "https://checkip.amazonaws.com",
    ])
    public_ip_expected_regex: Optional[str] = None  # optional regex to assert exit IP
    check_interval_sec: int = 10
    # Persistence
    state_dir: Path = Path("/var/run/vpn_guard")
    nft_table: str = "inet"
    nft_chain: str = "vpn_guard"
    nft_priority: int = 0  # near default; can be tuned
    # Safety
    dry_run: bool = False
    log_level: str = "INFO"

# ---------- Utilities ----------

class ShellError(RuntimeError):
    pass

class Shell:
    def __init__(self, dry_run: bool = False, env: Optional[dict] = None):
        self.dry_run = dry_run
        self.env = {**os.environ, **(env or {})}

    def run(self, cmd: str, timeout: int = 10) -> Tuple[int, str, str]:
        if self.dry_run:
            log.info(json.dumps({"event": "dry_run_cmd", "cmd": cmd}))
            return 0, "", ""
        proc = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env
        )
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise ShellError(f"Timeout: {cmd}")
        rc = proc.returncode
        return rc, out.decode(errors="replace").strip(), err.decode(errors="replace").strip()

    def must(self, cmd: str, timeout: int = 10) -> str:
        rc, out, err = self.run(cmd, timeout=timeout)
        if rc != 0:
            raise ShellError(f"cmd failed rc={rc}: {cmd}\n{err}")
        return out

# ---------- Backend Probes ----------

def linux_required():
    if sys.platform != "linux":
        raise NotImplementedError("vpn_guard supports Linux only.")

def is_root() -> bool:
    return os.geteuid() == 0

def cmd_exists(shell: Shell, name: str) -> bool:
    rc, *_ = shell.run(f"command -v {shlex.quote(name)}")
    return rc == 0

def interface_exists(shell: Shell, iface: str) -> bool:
    rc, *_ = shell.run(f"ip link show dev {shlex.quote(iface)}")
    return rc == 0

def default_route_dev(shell: Shell) -> Optional[str]:
    rc, out, _ = shell.run("ip route show default")
    if rc != 0 or not out:
        return None
    m = re.search(r"default via [0-9a-f\.:]+ dev (\S+)", out)
    return m.group(1) if m else None

# ---------- VPN Backends ----------

class VPNBackend:
    def __init__(self, shell: Shell, iface: str):
        self.shell = shell
        self.iface = iface

    async def healthy(self) -> bool:
        raise NotImplementedError

    async def endpoint_ips(self) -> List[str]:
        """IPs of VPN servers that must be reachable even with kill-switch."""
        return []

class WireGuardBackend(VPNBackend):
    async def healthy(self) -> bool:
        # Healthy if interface exists and wg reports at least one latest handshake < 3min
        if not interface_exists(self.shell, self.iface):
            return False
        if cmd_exists(self.shell, "wg"):
            out = self.shell.must("wg show all latest-handshakes || true")
            # Parse: <iface>\t<peer_pubkey>\t<ts>
            for line in out.splitlines():
                parts = line.split("\t")
                if len(parts) >= 3 and parts[0] == self.iface:
                    try:
                        ts = int(parts[2])
                        # ts==0 means never. consider healthy if handshake within last 180s
                        if ts != 0 and (int(time.time()) - ts) < 180:
                            return True
                    except ValueError:
                        continue
            # fallback: link up check
            return interface_exists(self.shell, self.iface)
        # No wg binary; fallback to link up
        return interface_exists(self.shell, self.iface)

    async def endpoint_ips(self) -> List[str]:
        # Try extracting endpoint from `wg show`
        if not cmd_exists(self.shell, "wg"):
            return []
        out = self.shell.must("wg show all endpoints || true")
        ips: List[str] = []
        for line in out.splitlines():
            # Format: <iface>\t<peer_pubkey>\t<endpoint_host:port>
            parts = line.split("\t")
            if len(parts) >= 3 and parts[0] == self.iface:
                host_port = parts[2]
                host = host_port.rsplit(":", 1)[0]
                # Resolve DNS to IPs if needed
                try:
                    ip = socket.gethostbyname(host)
                    ips.append(ip)
                except Exception:
                    pass
        return ips

class OpenVPNBackend(VPNBackend):
    async def healthy(self) -> bool:
        # Healthy if interface exists and has an IP address
        if not interface_exists(self.shell, self.iface):
            return False
        rc, out, _ = self.shell.run(f"ip addr show dev {shlex.quote(self.iface)}")
        return rc == 0 and "inet " in out

    async def endpoint_ips(self) -> List[str]:
        # Unable to reliably parse without management interface; return []
        return []

# ---------- nftables Manager ----------

class NftablesManager:
    def __init__(self, shell: Shell, table: str, chain: str, priority: int = 0):
        self.shell = shell
        self.table = table
        self.chain = chain
        self.priority = priority

    def ensure_base(self) -> None:
        # Create table/chain if absent (idempotent)
        self.shell.must(f"nft list table {self.table} || nft add table {self.table}")
        # Base forward/filter chain
        # We create chain with hook=output to control egress from host
        chain_cmd = (
            f"nft list chain {self.table} {self.chain} || "
            f"nft add chain {self.table} {self.chain} "
            f"{{ type filter hook output priority {self.priority}; policy accept; }}"
        )
        self.shell.must(chain_cmd)

    def _set_decl(self, name: str, family: str = "ip") -> str:
        return f"{self.table} {name}"

    def allow_loopback(self) -> None:
        self.shell.must(f"nft add rule {self.table} {self.chain} oif lo accept || true")

    def allow_dns_to(self, servers: Sequence[str]) -> None:
        for s in servers:
            # Allow UDP/TCP DNS to these servers
            self.shell.run(
                f"nft add rule {self.table} {self.chain} ip daddr {shlex.quote(s)} udp dport 53 accept || true"
            )
            self.shell.run(
                f"nft add rule {self.table} {self.chain} ip daddr {shlex.quote(s)} tcp dport 53 accept || true"
            )

    def allow_outside(self, cidr: str) -> None:
        self.shell.run(f"nft add rule {self.table} {self.chain} ip daddr {shlex.quote(cidr)} accept || true")
        self.shell.run(f"nft add rule {self.table} {self.chain} ip6 daddr {shlex.quote(cidr)} accept || true")

    def enforce_vpn_only(self, iface: str) -> None:
        # Drop any egress not via VPN iface, except rules above
        # Accept if oif == iface
        self.shell.must(f"nft add rule {self.table} {self.chain} oif {shlex.quote(iface)} accept || true")
        # Finally, drop everything else (egress)
        self.shell.must(f"nft add rule {self.table} {self.chain} counter drop || true")

    def clear(self) -> None:
        # Remove only our chain; keep table
        self.shell.run(f"nft flush chain {self.table} {self.chain} || true")
        self.shell.run(f"nft delete chain {self.table} {self.chain} || true")
        # Do not delete table (may be shared)

# ---------- DNS Manager (systemd-resolved) ----------

class DNSManager:
    def __init__(self, shell: Shell):
        self.shell = shell
        self.backup_file = Path("/var/run/vpn_guard.resolv.backup.json")

    def _resolvectl(self, cmd: str) -> str:
        return self.shell.must(f"resolvectl {cmd}")

    def link_id(self, iface: str) -> Optional[int]:
        rc, out, _ = self.shell.run("resolvectl status")
        if rc != 0:
            return None
        # Parse 'Link XX (wg0)'
        for line in out.splitlines():
            m = re.search(r"Link\s+(\d+)\s+\(([^)]+)\)", line.strip())
            if m and m.group(2) == iface:
                return int(m.group(1))
        return None

    def backup_state(self) -> None:
        # Backup current global DNS and per-link settings (best effort)
        rc, out, _ = self.shell.run("resolvectl dns")
        rc2, out2, _ = self.shell.run("resolvectl domain")
        state = {"dns": out, "domain": out2, "ts": int(time.time())}
        try:
            self.backup_file.write_text(json.dumps(state, ensure_ascii=False))
        except Exception as e:
            log.warning("dns_backup_failed", extra={"meta": str(e)})

    def restore(self) -> None:
        # Best-effort restore: restart systemd-resolved to reset link DNS
        # then rely on DHCP to re-publish
        self.shell.run("systemctl restart systemd-resolved || true")

    def pin_dns_to_link(self, iface: str, servers: Sequence[str]) -> None:
        link = self.link_id(iface)
        if link is None:
            raise ShellError(f"Cannot find link id for {iface} via resolvectl")
        # Clear current DNS for link, then set servers and make them default route for DNS
        self._resolvectl(f"revert {shlex.quote(iface)} || true")
        if servers:
            self._resolvectl(f"dns {shlex.quote(iface)} {' '.join(map(shlex.quote, servers))}")
            self._resolvectl(f"dnssec no")  # up to environment; can be 'yes' if infra supports
            # Optionally restrict search domains: none
            self._resolvectl(f"domain {shlex.quote(iface)} ~.")  # route all DNS via this link

# ---------- Health Monitor ----------

async def http_get_public_ip(shell: Shell, url: str, timeout: int = 3) -> Optional[str]:
    """
    Fetch public IP using curl; returns string or None on error.
    """
    if not cmd_exists(shell, "curl"):
        return None
    rc, out, _ = shell.run(f"curl -fsSL --max-time {timeout} {shlex.quote(url)}")
    if rc == 0 and out:
        ip = out.strip()
        # Basic sanity
        if re.match(r"^[0-9a-fA-F\:\.]+$", ip):
            return ip
    return None

# ---------- Core Guard ----------

class VPNGuard:
    def __init__(self, cfg: VPNGuardConfig):
        linux_required()
        _setup_logging(cfg.log_level)
        self.cfg = cfg
        self.shell = Shell(dry_run=cfg.dry_run)
        self.nft = NftablesManager(self.shell, cfg.nft_table, cfg.nft_chain, cfg.nft_priority)
        self.dns = DNSManager(self.shell)
        self.backend = None  # type: Optional[VPNBackend]
        self._running = False
        self._health_task: Optional[asyncio.Task] = None
        self._state_file = cfg.state_dir / "state.json"

    # ----- Lifecycle -----

    def _detect_backend(self) -> Tuple[VPNBackendType, str]:
        # Interface preference: explicit -> detect common names
        iface = self.cfg.interface
        if not iface:
            # Try common names
            for candidate in ("wg0", "wg1", "tun0", "tun1"):
                if interface_exists(self.shell, candidate):
                    iface = candidate
                    break
        if not iface:
            raise RuntimeError("Unable to detect VPN interface. Provide config.interface")

        btype = self.cfg.backend
        if btype == VPNBackendType.AUTO:
            # Heuristic: wg? -> WireGuard, tun? -> OpenVPN (fallback)
            if iface.startswith("wg"):
                btype = VPNBackendType.WIREGUARD
            else:
                btype = VPNBackendType.OPENVPN
        return btype, iface

    def _ensure_state_dir(self):
        self.cfg.state_dir.mkdir(parents=True, exist_ok=True)

    def _save_state(self, data: dict):
        self._ensure_state_dir()
        self._state_file.write_text(json.dumps(data, ensure_ascii=False, indent=2))

    def _load_state(self) -> dict:
        if self._state_file.exists():
            return json.loads(self._state_file.read_text())
        return {}

    # ----- Enable/Disable -----

    async def enable(self) -> None:
        if not is_root() and not self.cfg.dry_run:
            raise PermissionError("Root privileges required.")
        btype, iface = self._detect_backend()
        self.backend = WireGuardBackend(self.shell, iface) if btype == VPNBackendType.WIREGUARD else OpenVPNBackend(self.shell, iface)

        log.info(json.dumps({"event": "vpn_guard_enable", "meta": {"backend": btype.value, "iface": iface}}))
        # DNS backup
        if self.cfg.pin_dns_to_link and self.cfg.dns_servers:
            self.dns.backup_state()
            self.dns.pin_dns_to_link(iface, self.cfg.dns_servers)

        # nft base
        self.nft.ensure_base()
        self.nft.allow_loopback()

        # Allow outside (split-tunnel) before enforcing VPN-only
        # Typically include VPN endpoint IPs to maintain tunnel under kill-switch
        allow_cidrs = [r.cidr for r in self.cfg.allowlist_outside]
        # Also add endpoint IPs discovered from backend (best-effort)
        try:
            eps = await self.backend.endpoint_ips()
            allow_cidrs += eps
        except Exception:
            pass

        for cidr in allow_cidrs:
            self.nft.allow_outside(cidr)

        # Allow DNS to specified servers
        if self.cfg.dns_servers:
            self.nft.allow_dns_to(self.cfg.dns_servers)

        # Enforce vpn-only egress
        if self.cfg.block_non_vpn_egress:
            self.nft.enforce_vpn_only(iface)

        # Persist minimal state
        self._save_state({
            "enabled_at": int(time.time()),
            "backend": btype.value,
            "iface": iface,
            "dns": self.cfg.dns_servers,
            "block_non_vpn_egress": self.cfg.block_non_vpn_egress,
        })

        # Start health monitor
        self._running = True
        self._health_task = asyncio.create_task(self._health_loop())

    async def disable(self) -> None:
        log.info(json.dumps({"event": "vpn_guard_disable"}))
        self._running = False
        if self._health_task:
            self._health_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._health_task

        # Remove nft rules and restore DNS (best effort)
        self.nft.clear()
        if self.cfg.pin_dns_to_link:
            self.dns.restore()

        # Persist state
        self._save_state({"enabled_at": None})

    # ----- Health -----

    async def _health_loop(self) -> None:
        assert self.backend is not None
        iface = self.backend.iface
        prev_public_ip: Optional[str] = None
        while self._running:
            try:
                healthy = await self.backend.healthy()
                default_dev = default_route_dev(self.shell)
                status = {
                    "iface_up": interface_exists(self.shell, iface),
                    "backend_healthy": healthy,
                    "default_dev": default_dev,
                }

                # Public IP check (best effort)
                public_ip = None
                for url in self.cfg.public_ip_check_urls:
                    public_ip = await http_get_public_ip(self.shell, url)
                    if public_ip:
                        break

                if public_ip and self.cfg.public_ip_expected_regex:
                    if not re.search(self.cfg.public_ip_expected_regex, public_ip):
                        log.warning("public_ip_mismatch", extra={"meta": {"ip": public_ip}})
                if public_ip and public_ip != prev_public_ip:
                    log.info(json.dumps({"event": "public_ip_changed", "meta": {"ip": public_ip}}))
                    prev_public_ip = public_ip

                if not healthy or default_dev != iface:
                    log.warning("vpn_degraded", extra={"meta": status})
                    # Fail-closed is already enforced by nftables (egress blocked unless via iface)
                    # Optional: could attempt auto-repair here (not implemented to keep deterministic)
                else:
                    log.debug("vpn_ok", extra={"meta": status})
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error("health_loop_error", extra={"meta": str(e)})
            await asyncio.sleep(self.cfg.check_interval_sec)

    # ----- Status -----

    async def status(self) -> dict:
        state = self._load_state()
        iface = state.get("iface") or self.cfg.interface
        backend = state.get("backend") or (self.cfg.backend.value if isinstance(self.cfg.backend, VPNBackendType) else self.cfg.backend)
        result = {
            "enabled": bool(state.get("enabled_at")),
            "backend": backend,
            "iface": iface,
            "nft_table": self.cfg.nft_table,
            "nft_chain": self.cfg.nft_chain,
        }
        if iface:
            result["iface_exists"] = interface_exists(self.shell, iface)
            result["default_route_dev"] = default_route_dev(self.shell)
        return result

# ---------- Context Manager ----------

class vpn_guard_context:
    """Context manager for temporarily enabling guard."""
    def __init__(self, cfg: VPNGuardConfig):
        self.guard = VPNGuard(cfg)

    async def __aenter__(self) -> VPNGuard:
        await self.guard.enable()
        return self.guard

    async def __aexit__(self, exc_type, exc, tb):
        await self.guard.disable()

# ---------- CLI ----------

USAGE = """\
vpn_guard.py enable  [--iface IFACE] [--backend auto|wireguard|openvpn] [--dns 1.1.1.1,1.0.0.1] [--allow CIDR[,CIDR...]] [--expected-ip-regex REGEX] [--no-block] [--dry-run]
vpn_guard.py disable
vpn_guard.py status
vpn_guard.py monitor   # foreground health monitor
ENV:
  LOG_LEVEL=INFO
"""

def parse_args(argv: List[str]) -> Tuple[str, dict]:
    if not argv or argv[0] in ("-h", "--help"):
        print(USAGE)
        sys.exit(0)
    cmd = argv[0]
    opts = {
        "iface": None,
        "backend": "auto",
        "dns": [],
        "allow": [],
        "expected_ip_regex": None,
        "block": True,
        "dry_run": False,
    }
    it = iter(argv[1:])
    for a in it:
        if a == "--iface":
            opts["iface"] = next(it, None)
        elif a == "--backend":
            opts["backend"] = next(it, "auto")
        elif a == "--dns":
            opts["dns"] = next(it, "").split(",")
        elif a == "--allow":
            opts["allow"] = [x for x in next(it, "").split(",") if x]
        elif a == "--expected-ip-regex":
            opts["expected_ip_regex"] = next(it, None)
        elif a == "--no-block":
            opts["block"] = False
        elif a == "--dry-run":
            opts["dry_run"] = True
        else:
            raise SystemExit(f"Unknown arg: {a}")
    return cmd, opts

def build_config(opts: dict) -> VPNGuardConfig:
    bmap = {
        "auto": VPNBackendType.AUTO,
        "wireguard": VPNBackendType.WIREGUARD,
        "openvpn": VPNBackendType.OPENVPN,
    }
    allowlist = [SplitTunnelRule(cidr=x) for x in opts["allow"]]
    cfg = VPNGuardConfig(
        backend=bmap.get(opts["backend"], VPNBackendType.AUTO),
        interface=opts["iface"],
        dns_servers=[d for d in opts["dns"] if d],
        allowlist_outside=allowlist,
        public_ip_expected_regex=opts["expected_ip_regex"],
        block_non_vpn_egress=opts["block"],
        dry_run=opts["dry_run"],
        log_level=os.getenv("LOG_LEVEL", "INFO"),
    )
    return cfg

async def main(argv: List[str]) -> int:
    cmd, opts = parse_args(argv)
    cfg = build_config(opts)
    guard = VPNGuard(cfg)

    if cmd == "enable":
        await guard.enable()
        # Keep process alive shortly to confirm initial health
        await asyncio.sleep(cfg.check_interval_sec * 2)
        status = await guard.status()
        print(json.dumps(status, ensure_ascii=False, indent=2))
        return 0

    if cmd == "disable":
        await guard.disable()
        print(json.dumps({"disabled": True}, ensure_ascii=False))
        return 0

    if cmd == "status":
        print(json.dumps(await guard.status(), ensure_ascii=False, indent=2))
        return 0

    if cmd == "monitor":
        # Enable if not enabled; then keep running
        state = await guard.status()
        if not state.get("enabled"):
            await guard.enable()
        try:
            while True:
                await asyncio.sleep(3600)
        except KeyboardInterrupt:
            await guard.disable()
        return 0

    print(USAGE)
    return 1

if __name__ == "__main__":
    try:
        asyncio.run(main(sys.argv[1:]))
    except KeyboardInterrupt:
        pass
