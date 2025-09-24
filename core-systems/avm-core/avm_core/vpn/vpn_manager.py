# core-systems/avm_core/vpn/vpn_manager.py
# Industrial VPN tunnel manager for Aethernova AVM
from __future__ import annotations

import os
import re
import time
import json
import socket
import signal
import threading
import subprocess
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Tuple, List

import yaml

try:
    from prometheus_client import Gauge, Counter
except Exception:  # pragma: no cover
    # allow running without prometheus in minimal envs
    class _N:  # noqa: N801
        def __init__(self, *_, **__): ...
        def labels(self, *_, **__): return self
        def set(self, *_): ...
        def inc(self, *_): ...
    Gauge = Counter = _N  # type: ignore

try:
    # project logger (structlog)
    from avm_core.logging_setup import log
except Exception:  # pragma: no cover
    # fallback simple logger
    import logging
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    class _L:
        def info(self, *a, **k): logging.info(json.dumps({"level": "info", "msg": a[0] if a else "", **k}))
        def warning(self, *a, **k): logging.warning(json.dumps({"level": "warning", "msg": a[0] if a else "", **k}))
        def error(self, *a, **k): logging.error(json.dumps({"level": "error", "msg": a[0] if a else "", **k}))
    log = _L()  # type: ignore


# =========================
# Metrics
# =========================
VPN_CONNECTED = Gauge("avm_vpn_connected", "Is VPN connected (1/0)", ["profile", "provider", "iface"])
VPN_RX = Gauge("avm_vpn_rx_bytes", "VPN RX bytes", ["profile", "provider", "iface"])
VPN_TX = Gauge("avm_vpn_tx_bytes", "VPN TX bytes", ["profile", "provider", "iface"])
VPN_LAST_HANDSHAKE = Gauge("avm_vpn_last_handshake", "Last handshake epoch seconds", ["profile", "provider", "iface"])
VPN_RECONNECTS = Counter("avm_vpn_reconnects_total", "Reconnects count", ["profile", "provider"])
VPN_ERRORS = Counter("avm_vpn_errors_total", "Errors count", ["profile", "provider"])
VPN_KILLSWITCH = Gauge("avm_vpn_killswitch_enabled", "Kill-switch state (1/0)", ["profile"])


# =========================
# Data types
# =========================
@dataclass
class VpnStatus:
    connected: bool
    profile: str
    provider: str
    iface: Optional[str] = None
    endpoint: Optional[str] = None
    peer_public_key: Optional[str] = None
    rx_bytes: int = 0
    tx_bytes: int = 0
    last_handshake_epoch: int = 0
    since_epoch: int = field(default_factory=lambda: int(time.time()))
    extra: Dict[str, Any] = field(default_factory=dict)


# =========================
# Exceptions
# =========================
class VpnError(RuntimeError): ...
class VpnConfigError(ValueError): ...
class KillSwitchError(RuntimeError): ...


# =========================
# Utilities
# =========================
def _run(cmd: List[str], check: bool = True) -> Tuple[int, str, str]:
    """Run a command returning (code, stdout, stderr). Raises if check=True and code!=0."""
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and proc.returncode != 0:
        raise VpnError(f"cmd failed: {' '.join(cmd)} :: {proc.stderr.strip()}")
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def _resolve_host(hostport: str) -> Tuple[str, int, str]:
    """Resolve 'host:port' → (ip, port, family)."""
    if ":" not in hostport:
        raise VpnConfigError("endpoint must be 'host:port'")
    host, port_s = hostport.rsplit(":", 1)
    port = int(port_s)
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    # prefer IPv4 for iptables simplicity (we handle v6 below separately)
    infos.sort(key=lambda i: 0 if i[0] == socket.AF_INET else 1)
    ip = infos[0][4][0]
    fam = "ipv4" if infos[0][0] == socket.AF_INET else "ipv6"
    return ip, port, fam


def _read_yaml(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        raise VpnConfigError(f"config not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _ensure_root():
    if os.geteuid() != 0:
        raise VpnError("vpn_manager requires root or CAP_NET_ADMIN")


# =========================
# Kill-switch (iptables)
# =========================
class KillSwitch:
    CHAIN_V4 = "AVM-KS-OUT"
    CHAIN_V6 = "AVM-KS6-OUT"

    def __init__(self) -> None:
        self.enabled = False
        self.allowed_endpoint: Optional[Tuple[str, int, str]] = None
        self.iface: Optional[str] = None
        self.lock = threading.RLock()

    def _ipt(self, v6: bool, *args: str) -> None:
        tool = "ip6tables" if v6 else "iptables"
        _run([tool, *args])

    def _create_chain(self, v6: bool) -> None:
        chain = self.CHAIN_V6 if v6 else self.CHAIN_V4
        # create chain if not exists
        _run(["bash", "-lc", f"{'ip6tables' if v6 else 'iptables'} -N {chain} 2>/dev/null || true"], check=False)
        # ensure OUTPUT jumps into our chain exactly once
        _, rules, _ = _run([('ip6tables' if v6 else 'iptables'), "-S", "OUTPUT"])
        if f"-j {chain}" not in rules:
            self._ipt(v6, "-I", "OUTPUT", "1", "-j", chain)

    def _flush_chain(self, v6: bool) -> None:
        chain = self.CHAIN_V6 if v6 else self.CHAIN_V4
        self._ipt(v6, "-F", chain)

    def _delete_chain(self, v6: bool) -> None:
        chain = self.CHAIN_V6 if v6 else self.CHAIN_V4
        # remove jump from OUTPUT
        _run(["bash", "-lc", f"{'ip6tables' if v6 else 'iptables'} -D OUTPUT -j {chain} 2>/dev/null || true"], check=False)
        # flush and delete chain
        _run(["bash", "-lc", f"{'ip6tables' if v6 else 'iptables'} -F {chain} 2>/dev/null || true"], check=False)
        _run(["bash", "-lc", f"{'ip6tables' if v6 else 'iptables'} -X {chain} 2>/dev/null || true"], check=False)

    def enable_pre_connect(self, endpoint: Tuple[str, int, str]) -> None:
        """Strict mode before connect: drop all egress except DNS and VPN endpoint handshake."""
        with self.lock:
            _ensure_root()
            self.allowed_endpoint = endpoint
            for v6 in (False, True):
                self._create_chain(v6)
                self._flush_chain(v6)
                chain = self.CHAIN_V6 if v6 else self.CHAIN_V4

                # Allow loopback
                self._ipt(v6, "-A", chain, "-o", "lo", "-j", "ACCEPT")
                # Allow established/related
                self._ipt(v6, "-A", chain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
                # Allow DNS to configured resolvers (optional; many systems use local resolver)
                # Safe default: allow only localhost DNS
                self._ipt(v6, "-A", chain, "-p", "udp", "--dport", "53", "-d", "127.0.0.1" if not v6 else "::1", "-j", "ACCEPT")

                # Allow UDP handshake to endpoint
                ip, port, fam = endpoint
                if fam == ("ipv6" if v6 else "ipv4"):
                    self._ipt(v6, "-A", chain, "-p", "udp", "-d", ip, "--dport", str(port), "-j", "ACCEPT")

                # Finally, drop everything
                self._ipt(v6, "-A", chain, "-j", "DROP")

            self.enabled = True
            VPN_KILLSWITCH.labels(profile="pre").set(1)
            log.info("killswitch_pre_enabled", endpoint={"ip": endpoint[0], "port": endpoint[1], "fam": endpoint[2]})

    def switch_to_iface_only(self, iface: str) -> None:
        """Post-connect mode: allow egress only via VPN iface (except loopback)."""
        with self.lock:
            _ensure_root()
            self.iface = iface
            for v6 in (False, True):
                self._create_chain(v6)
                self._flush_chain(v6)
                chain = self.CHAIN_V6 if v6 else self.CHAIN_V4

                # Allow loopback
                self._ipt(v6, "-A", chain, "-o", "lo", "-j", "ACCEPT")
                # Allow established/related
                self._ipt(v6, "-A", chain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
                # Allow egress ONLY via VPN iface
                self._ipt(v6, "-A", chain, "-o", iface, "-j", "ACCEPT")
                # Drop all others
                self._ipt(v6, "-A", chain, "-j", "DROP")

            VPN_KILLSWITCH.labels(profile="post").set(1)
            log.info("killswitch_post_enabled", iface=iface)

    def disable(self) -> None:
        with self.lock:
            for v6 in (False, True):
                self._delete_chain(v6)
            self.enabled = False
            self.allowed_endpoint = None
            self.iface = None
            VPN_KILLSWITCH.labels(profile="post").set(0)
            VPN_KILLSWITCH.labels(profile="pre").set(0)
            log.info("killswitch_disabled")


# =========================
# Providers
# =========================
class BaseProvider:
    name = "base"
    def up(self) -> VpnStatus: raise NotImplementedError
    def down(self) -> None: raise NotImplementedError
    def status(self) -> VpnStatus: raise NotImplementedError


class WireGuardProvider(BaseProvider):
    """WireGuard provider using 'ip' + 'wg' utilities and configs/network/wireguard.yaml."""
    name = "wireguard"

    def __init__(self, profile_name: str, profile_cfg: Dict[str, Any], wg_cfg_path: str = "configs/network/wireguard.yaml"):
        self.profile = profile_name
        self.profile_cfg = profile_cfg or {}
        self.cfg = _read_yaml(wg_cfg_path)
        self.iface = self.profile_cfg.get("iface") or self.cfg.get("iface") or "avmwg0"
        self.endpoint = self.cfg.get("endpoint")
        if not self.endpoint:
            raise VpnConfigError("wireguard endpoint is required in wireguard.yaml")
        self._privkey_ref = self.cfg.get("private_key_ref")
        self._preshared_key_ref = self.cfg.get("preshared_key_ref", "")
        self._started = False

    # ---- helpers
    def _ip(self, *args: str) -> None:
        _run(["ip", *args])

    def _wg(self, *args: str) -> str:
        _, out, _ = _run(["wg", *args])
        return out

    def _secret_value(self, ref: str) -> str:
        """Integrate with your secret broker; here read ENV as example."""
        if not ref:
            return ""
        if ref.startswith("vault://"):
            env_name = "AVM_WG_PRIVKEY" if "private_key" in ref else "AVM_WG_PSK"
            val = os.getenv(env_name, "")
            if not val:
                raise VpnConfigError(f"secret not provided via env {env_name}")
            return val.strip()
        return ref

    def _ensure_iface(self) -> None:
        try:
            self._ip("link", "add", self.iface, "type", "wireguard")
        except VpnError as e:
            if "File exists" not in str(e):
                raise

        # addresses
        for addr in self.cfg.get("addresses", []):
            try:
                self._ip("address", "add", addr, "dev", self.iface)
            except VpnError as e:
                if "File exists" not in str(e):
                    raise

        mtu = str(self.cfg.get("mtu", 1380))
        self._ip("link", "set", "mtu", mtu, "dev", self.iface)

    def _configure_peer(self) -> None:
        priv = self._secret_value(self._privkey_ref)
        if not priv:
            raise VpnConfigError("wireguard private key is empty")
        os.makedirs("/run/avm", exist_ok=True)
        keyfile = f"/run/avm/{self.iface}.key"
        with open(keyfile, "w", encoding="utf-8") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(priv)

        _run(["wg", "set", self.iface, "private-key", keyfile])

        peer_pub = self.cfg.get("peer_public_key")
        allowed_ips = ",".join(self.cfg.get("allowed_ips", ["0.0.0.0/0", "::/0"]))
        keepalive = str(self.cfg.get("persistent_keepalive", 25))

        args = ["set", self.iface, "peer", peer_pub, "allowed-ips", allowed_ips, "endpoint", self.endpoint, "persistent-keepalive", keepalive]
        psk = self._secret_value(self._preshared_key_ref)
        if psk:
            # write PSK temp file
            pskfile = f"/run/avm/{self.iface}.psk"
            with open(pskfile, "w", encoding="utf-8") as f:
                os.fchmod(f.fileno(), 0o600)
                f.write(psk)
            args += ["preshared-key", pskfile]

        _run(["wg", *args])

    def up(self) -> VpnStatus:
        _ensure_root()
        self._ensure_iface()
        self._configure_peer()
        self._ip("link", "set", "up", "dev", self.iface)

        # set DNS (optional; best via resolvconf/systemd-resolved by operator)
        # status
        st = self.status()
        self._started = True
        return st

    def down(self) -> None:
        _ensure_root()
        try:
            self._ip("link", "set", "down", "dev", self.iface)
        finally:
            _run(["bash", "-lc", f"ip link del {self.iface} 2>/dev/null || true"], check=False)
            self._started = False

    def status(self) -> VpnStatus:
        _, out, _ = _run(["wg", "show", self.iface], check=False)
        connected = False
        peer = None
        endpoint = None
        rx = tx = 0
        last_hs = 0
        for line in out.splitlines():
            if line.startswith("peer:"):
                peer = line.split("peer:")[1].strip()
            elif "endpoint:" in line:
                endpoint = line.split("endpoint:")[1].strip()
                connected = True
            elif "transfer:" in line:
                m = re.findall(r"(\d+)\s*received,.*?(\d+)\s*sent", line)
                if m:
                    rx, tx = map(int, m[0])
            elif "latest handshake:" in line:
                # convert to epoch if possible (wg may print 'now')
                if "now" in line:
                    last_hs = int(time.time())
        st = VpnStatus(
            connected=connected,
            profile=self.profile,
            provider=self.name,
            iface=self.iface,
            endpoint=endpoint or self.endpoint,
            peer_public_key=peer,
            rx_bytes=rx,
            tx_bytes=tx,
            last_handshake_epoch=last_hs,
        )
        VPN_CONNECTED.labels(self.profile, self.name, self.iface).set(1 if connected else 0)
        VPN_RX.labels(self.profile, self.name, self.iface).set(rx)
        VPN_TX.labels(self.profile, self.name, self.iface).set(tx)
        if last_hs:
            VPN_LAST_HANDSHAKE.labels(self.profile, self.name, self.iface).set(last_hs)
        return st


class OpenVPNProvider(BaseProvider):
    """Minimal OpenVPN adapter; expects a ready .ovpn config path in profile."""
    name = "openvpn"

    def __init__(self, profile_name: str, profile_cfg: Dict[str, Any]):
        self.profile = profile_name
        self.cfg = profile_cfg or {}
        self.conf_path = self.cfg.get("config_path")
        if not self.conf_path:
            raise VpnConfigError("openvpn requires config_path in profile")
        self.mgmt_host = self.cfg.get("management_host", "127.0.0.1")
        self.mgmt_port = int(self.cfg.get("management_port", 7505))
        self.proc: Optional[subprocess.Popen] = None
        self.iface = self.cfg.get("iface", "tun0")

    def up(self) -> VpnStatus:
        _ensure_root()
        if self.proc and self.proc.poll() is None:
            return self.status()
        # start daemonized OpenVPN; recommend using --management
        args = ["openvpn", "--config", self.conf_path, "--daemon", "avm-openvpn", "--management", f"{self.mgmt_host}", str(self.mgmt_port)]
        _run(args)
        time.sleep(1.5)
        return self.status()

    def down(self) -> None:
        _ensure_root()
        # try management interface
        try:
            with socket.create_connection((self.mgmt_host, self.mgmt_port), timeout=2) as s:
                s.sendall(b"signal SIGTERM\n")
        except Exception:
            # fallback: killall
            _run(["pkill", "-f", "avm-openvpn"], check=False)

    def status(self) -> VpnStatus:
        connected = False
        rx = tx = 0
        last_hs = 0
        endpoint = None
        # try reading ifconfig
        code, out, _ = _run(["bash", "-lc", f"ip addr show {self.iface} | grep 'inet\\b'"], check=False)
        if code == 0 and out.strip():
            connected = True
        # bytes via /sys/class/net
        try:
            with open(f"/sys/class/net/{self.iface}/statistics/rx_bytes", "r") as f:
                rx = int(f.read().strip())
            with open(f"/sys/class/net/{self.iface}/statistics/tx_bytes", "r") as f:
                tx = int(f.read().strip())
        except Exception:
            pass
        st = VpnStatus(
            connected=connected,
            profile=self.profile,
            provider=self.name,
            iface=self.iface,
            endpoint=endpoint,
            rx_bytes=rx,
            tx_bytes=tx,
            last_handshake_epoch=last_hs,
        )
        VPN_CONNECTED.labels(self.profile, self.name, self.iface).set(1 if connected else 0)
        VPN_RX.labels(self.profile, self.name, self.iface).set(rx)
        VPN_TX.labels(self.profile, self.name, self.iface).set(tx)
        return st


# =========================
# Manager
# =========================
class VpnManager:
    """
    High-availability VPN Manager.

    Config expectations:
      profiles file: configs/network/profiles.yaml
        profiles:
          wireguard:
            provider: "wireguard"
            iface: "avmwg0"
            enforce_killswitch: true
          openvpn:
            provider: "openvpn"
            config_path: "configs/network/client.ovpn"
            iface: "tun0"
            enforce_killswitch: true
    """

    def __init__(self, profiles_path: str = "configs/network/profiles.yaml", wg_cfg_path: str = "configs/network/wireguard.yaml"):
        self._lock = threading.RLock()
        self._profiles_path = profiles_path
        self._wg_cfg_path = wg_cfg_path
        self._active_profile: Optional[str] = None
        self._provider: Optional[BaseProvider] = None
        self._killswitch = KillSwitch()
        self._stop_flag = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None
        self._last_status: Optional[VpnStatus] = None
        self._backoff = Backoff()

        cfg = _read_yaml(self._profiles_path)
        self._default = cfg.get("default", "wireguard")
        self._profiles = cfg.get("profiles", {})
        if not self._profiles:
            raise VpnConfigError("no profiles defined in profiles.yaml")

    # --------- Provider factory
    def _build_provider(self, profile_name: str) -> BaseProvider:
        p = self._profiles.get(profile_name)
        if not p:
            raise VpnConfigError(f"profile not found: {profile_name}")
        provider = p.get("provider")
        if provider == "wireguard":
            return WireGuardProvider(profile_name, p, wg_cfg_path=self._wg_cfg_path)
        if provider == "openvpn":
            return OpenVPNProvider(profile_name, p)
        raise VpnConfigError(f"unknown provider: {provider}")

    # --------- Public API
    def up(self, profile: Optional[str] = None) -> VpnStatus:
        """
        Bring VPN up with kill-switch protection and start health monitoring.
        """
        with self._lock:
            profile = profile or self._default
            if self._provider:
                raise VpnError(f"VPN already active: {self._active_profile}")
            provider = self._build_provider(profile)

            # Pre-connect kill-switch allowing only endpoint handshake (WireGuard)
            if isinstance(provider, WireGuardProvider):
                endpoint = _resolve_host(provider.endpoint)
                self._killswitch.enable_pre_connect(endpoint)

            st = provider.up()

            # Post-connect kill-switch
            if self._profiles[profile].get("enforce_killswitch", True):
                self._killswitch.switch_to_iface_only(st.iface or "unknown")

            self._provider = provider
            self._active_profile = profile
            self._stop_flag.clear()
            self._start_monitoring_thread()
            log.info("vpn_up", profile=profile, provider=provider.name, status=st.__dict__)
            return st

    def down(self) -> None:
        """
        Tear VPN down and stop monitoring, then disable kill-switch.
        """
        with self._lock:
            self._stop_flag.set()
            if self._monitor_thread and self._monitor_thread.is_alive():
                self._monitor_thread.join(timeout=2.0)
            if self._provider:
                try:
                    self._provider.down()
                finally:
                    self._provider = None
                    self._active_profile = None
                    self._last_status = None
            self._killswitch.disable()
            log.info("vpn_down")

    def status(self) -> Dict[str, Any]:
        with self._lock:
            if not self._provider:
                return {"active": False}
            st = self._provider.status()
            self._last_status = st
            return {
                "active": True,
                "status": st.__dict__,
            }

    def restart(self) -> VpnStatus:
        with self._lock:
            profile = self._active_profile
            self.down()
            time.sleep(0.5)
            return self.up(profile)

    # --------- Monitoring
    def _start_monitoring_thread(self) -> None:
        t = threading.Thread(target=self._monitor_loop, name="avm-vpn-monitor", daemon=True)
        self._monitor_thread = t
        t.start()

    def _monitor_loop(self) -> None:
        """Monitor health and reconnect if needed."""
        # thresholds
        handshake_timeout = 90   # seconds without handshake → reconnect
        check_interval_min = 5
        while not self._stop_flag.is_set():
            try:
                with self._lock:
                    if not self._provider:
                        break
                    st = self._provider.status()
                    self._last_status = st
                    iface = st.iface or "unknown"
                    VPN_CONNECTED.labels(st.profile, st.provider, iface).set(1 if st.connected else 0)

                    # reconnect conditions
                    now = int(time.time())
                    stale = st.last_handshake_epoch and (now - st.last_handshake_epoch > handshake_timeout)
                    if (not st.connected) or stale:
                        VPN_RECONNECTS.labels(st.profile, st.provider).inc()
                        log.warning("vpn_reconnect_trigger", reason="stale" if stale else "down", status=st.__dict__)
                        self._reconnect_locked()

                # adaptive sleep: faster after reconnect attempts
                time.sleep(max(check_interval_min, self._backoff.sleep_s))
                self._backoff.step(reset=True)  # gentle: reset unless reconnect occurred
            except Exception as e:  # pragma: no cover
                VPN_ERRORS.labels(self._active_profile or "unknown", getattr(self._provider, "name", "unknown")).inc()
                log.error("vpn_monitor_error", error=str(e))
                time.sleep(self._backoff.step())

    def _reconnect_locked(self) -> None:
        """Reconnect with backoff. Call with self._lock held."""
        prof = self._active_profile
        try:
            if self._provider:
                try:
                    self._provider.down()
                except Exception as e:
                    log.warning("vpn_down_error", error=str(e))
            time.sleep(0.3)
            self._provider = self._build_provider(prof or self._default)

            # Pre-connect kill-switch for WG only
            if isinstance(self._provider, WireGuardProvider):
                endpoint = _resolve_host(self._provider.endpoint)
                self._killswitch.enable_pre_connect(endpoint)

            st = self._provider.up()
            if self._profiles[prof or self._default].get("enforce_killswitch", True):
                self._killswitch.switch_to_iface_only(st.iface or "unknown")

            self._backoff.reset()
            log.info("vpn_reconnected", profile=prof, status=st.__dict__)
        except Exception as e:
            VPN_ERRORS.labels(prof or "unknown", getattr(self._provider, "name", "unknown")).inc()
            sleep_s = self._backoff.step()
            log.error("vpn_reconnect_failed", error=str(e), backoff_s=sleep_s)
            time.sleep(sleep_s)

# =========================
# Backoff helper
# =========================
class Backoff:
    def __init__(self, base: float = 1.0, factor: float = 2.0, max_s: float = 60.0) -> None:
        self.base = base
        self.factor = factor
        self.max_s = max_s
        self._n = 0
        self.sleep_s = base

    def step(self, reset: bool = False) -> float:
        if reset:
            self.reset()
            return self.sleep_s
        self._n += 1
        self.sleep_s = min(self.base * (self.factor ** self._n), self.max_s)
        return self.sleep_s

    def reset(self) -> None:
        self._n = 0
        self.sleep_s = self.base


# =========================
# Singleton accessor (for API layer)
# =========================
_global_manager: Optional[VpnManager] = None
def get_manager() -> VpnManager:
    global _global_manager
    if _global_manager is None:
        _global_manager = VpnManager()
    return _global_manager
