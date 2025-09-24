# cybersecurity-core/cybersecurity/asset_inventory/discovery.py
# -*- coding: utf-8 -*-
"""
Industrial-grade Asset Discovery Engine for cybersecurity-core.

Features:
- Async discovery engine orchestrating multiple probes per host:
  * ICMP reachability via OS 'ping' (no raw sockets)
  * TCP connect scan across curated ports with banner sniff (optional)
  * Optional SNMP sysName/sysDescr (if pysnmp is installed)
  * Optional SSDP M-SEARCH broadcast to discover local devices
- Strict Pydantic models (v2 preferred, v1 compatible)
- Concurrency & rate limiting (token bucket), per-host and global semaphores
- Reliable timeouts, retries (for probes), graceful cancellation
- Structured logging with correlation IDs; optional OpenTelemetry spans
- MAC resolution via ARP table (best-effort, OS-portable)
- Deterministic merge of probe results into Asset objects
- JSON-serializable DiscoveryReport with timing metadata

Dependencies:
    pydantic>=1.10 (v2 supported), no hard deps beyond stdlib
Optional:
    pysnmp>=4.4 (SNMP probe enabled if present)
    opentelemetry-api (tracing if present)
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, Type, TypeVar, Union

# --- Pydantic import with v2/v1 compatibility --------------------------------
try:
    from pydantic import BaseModel, Field, ValidationError  # type: ignore
    from pydantic import __version__ as _pyd_ver  # type: ignore

    PydanticV2 = _pyd_ver.startswith("2.")
except Exception:  # pragma: no cover
    from pydantic.v1 import BaseModel, Field, ValidationError  # type: ignore

    PydanticV2 = False

# --- Optional OpenTelemetry ---------------------------------------------------
try:
    from opentelemetry import trace  # type: ignore

    _tracer = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _tracer = None  # type: ignore

# --- Optional SNMP ------------------------------------------------------------
try:
    # Lazy usage in code; absence is fine.
    import pysnmp.hlapi.asyncio as snmp  # type: ignore

    _snmp_available = True
except Exception:  # pragma: no cover
    snmp = None  # type: ignore
    _snmp_available = False

# --- Logging ------------------------------------------------------------------
logger = logging.getLogger("asset_discovery")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    logger.addHandler(_h)
    logger.setLevel(os.getenv("ASSET_DISCOVERY_LOG_LEVEL", "INFO"))

# --- Utilities ----------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

class TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int) -> None:
        self.rate = float(rate_per_sec)
        self.capacity = int(burst)
        self._tokens = float(burst)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        async with self._lock:
            await self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return
            deficit = tokens - self._tokens
            wait_s = max(0.0, deficit / self.rate) if self.rate > 0 else 0.0
            if wait_s > 0:
                await asyncio.sleep(wait_s)
            await self._refill()
            self._tokens = max(0.0, self._tokens - tokens)

    async def _refill(self) -> None:
        now = time.monotonic()
        delta = now - self._last
        self._last = now
        self._tokens = min(self.capacity, self._tokens + delta * self.rate)

# --- Models -------------------------------------------------------------------
class Service(BaseModel):
    port: int
    proto: str = "tcp"
    banner: Optional[str] = None
    service: Optional[str] = None
    tls: Optional[bool] = None
    detected_at: datetime = Field(default_factory=now_utc)

class Asset(BaseModel):
    ip: str
    hostname: Optional[str] = None
    mac: Optional[str] = None
    vendor: Optional[str] = None
    os_guess: Optional[str] = None
    alive: bool = False
    services: List[Service] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    last_seen: datetime = Field(default_factory=now_utc)

class DiscoveryConfig(BaseModel):
    ports: List[int] = Field(
        default_factory=lambda: [22, 80, 443, 3389, 445, 139, 135, 8080, 8000, 8443, 3306, 5432, 6379, 27017]
    )
    ping_timeout_s: float = 1.2
    connect_timeout_s: float = 0.8
    banner_read_timeout_s: float = 0.5
    per_host_port_concurrency: int = 50
    global_host_concurrency: int = 512
    rate_limit_per_sec: float = 200.0
    rate_burst: int = 400
    retries_ping: int = 1
    retries_connect: int = 0
    banner_enabled: bool = True
    resolve_hostname: bool = True
    resolve_mac: bool = True
    snmp_enabled: bool = False
    snmp_communities: List[str] = Field(default_factory=lambda: ["public"])
    snmp_timeout_s: float = 0.8
    snmp_port: int = 161
    ssdp_enabled: bool = False
    ssdp_timeout_s: float = 1.0
    ssdp_mx: int = 1
    max_targets: int = 65536  # safety cap for huge CIDRs
    correlation_id: Optional[str] = None

class DiscoveryReport(BaseModel):
    started_at: datetime
    finished_at: datetime
    duration_s: float
    scanned_targets: int
    alive_hosts: int
    assets: List[Asset]

# --- OS helpers ---------------------------------------------------------------
def _platform_ping_args(timeout_s: float) -> List[str]:
    """Return platform-specific ping command args for 1 echo."""
    timeout_ms = max(100, int(timeout_s * 1000))
    system = platform.system().lower()
    if system == "windows":
        # -n 1 (count), -w timeout(ms)
        return ["ping", "-n", "1", "-w", str(timeout_ms)]
    # Linux/mac: -c 1, -W timeout(s) (Linux), macOS uses -W in ms? Use -W seconds on Linux, on macOS use -W milliseconds only with newer; fallback to -t?
    if system == "darwin":
        # macOS: -c 1, -W timeout(ms)
        return ["ping", "-c", "1", "-W", str(timeout_ms)]
    # Linux: -c 1, -W timeout(s)
    tout_s = max(1, int(round(timeout_s)))
    return ["ping", "-c", "1", "-W", str(tout_s)]

async def _run_ping(ip: str, timeout_s: float) -> bool:
    """Run system ping once; return True if host is reachable."""
    if not shutil.which("ping"):
        return await _tcp_ping_fallback(ip, timeout_s)
    args = _platform_ping_args(timeout_s) + [ip]
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout_s + 0.5)
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            return False
        return proc.returncode == 0
    except Exception:
        return False

async def _tcp_ping_fallback(ip: str, timeout_s: float) -> bool:
    """If ping unavailable, try to connect to common ports quickly."""
    for port in (80, 443, 22):
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout_s)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            return True
        except Exception:
            continue
    return False

def _parse_arp_for_mac(output: str, ip: str) -> Optional[str]:
    ip_re = re.escape(ip)
    # Common formats across OSes
    patterns = [
        rf"{ip_re}\s+\S+\s+([0-9a-fA-F:{{}}-]{{12,}})",  # linux: ip HWtype HWaddress
        rf"\(({ip_re})\)\s+at\s+([0-9a-fA-F:{{}}-]{{12,}})",  # macOS
        rf"{ip_re}\s+[-\w]+\s+([0-9A-Fa-f-]{{12,17}})",  # Windows
    ]
    for pat in patterns:
        m = re.search(pat, output)
        if not m:
            continue
        # Last group should be MAC
        mac = m.groups()[-1]
        # Normalize to AA:BB:CC:DD:EE:FF
        mac = mac.replace("-", ":").lower()
        parts = [p.zfill(2) for p in mac.split(":") if p]
        if len(parts) == 6:
            return ":".join(parts)
    return None

async def _resolve_mac(ip: str) -> Optional[str]:
    """Best-effort ARP resolution via system arp."""
    cmd = None
    if platform.system().lower() == "windows":
        cmd = ["arp", "-a", ip]
    else:
        cmd = ["arp", "-n", ip]
    if not shutil.which(cmd[0]):
        return None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=1.0)
        return _parse_arp_for_mac(out.decode(errors="ignore"), ip)
    except Exception:
        return None

async def _reverse_dns(ip: str, timeout_s: float = 0.5) -> Optional[str]:
    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(loop.getnameinfo((ip, 0), flags=0), timeout=timeout_s)  # type: ignore
    except Exception:
        # Fallback using gethostbyaddr in thread
        def _do() -> Optional[str]:
            try:
                return socket.gethostbyaddr(ip)[0]
            except Exception:
                return None
        try:
            return await asyncio.wait_for(loop.run_in_executor(None, _do), timeout=timeout_s)
        except Exception:
            return None

# --- Probes -------------------------------------------------------------------
class ProbeResult(BaseModel):
    alive: bool = False
    services: List[Service] = Field(default_factory=list)
    hostname: Optional[str] = None
    mac: Optional[str] = None
    os_guess: Optional[str] = None
    sources: Set[str] = Field(default_factory=set)  # type: ignore

class BaseProbe:
    name: str = "base"

    def __init__(self, cfg: DiscoveryConfig) -> None:
        self.cfg = cfg

    async def run(self, ip: str) -> ProbeResult:
        raise NotImplementedError

class PingProbe(BaseProbe):
    name = "icmp"

    async def run(self, ip: str) -> ProbeResult:
        alive = False
        for _ in range(max(1, self.cfg.retries_ping + 1)):
            if await _run_ping(ip, self.cfg.ping_timeout_s):
                alive = True
                break
        pr = ProbeResult(alive=alive, sources={"icmp"})
        if alive and self.cfg.resolve_hostname:
            host = await _reverse_dns(ip, timeout_s=0.8)
            if host:
                pr.hostname = host
        if alive and self.cfg.resolve_mac:
            mac = await _resolve_mac(ip)
            if mac:
                pr.mac = mac
        return pr

class TCPConnectProbe(BaseProbe):
    name = "tcp"

    def __init__(self, cfg: DiscoveryConfig) -> None:
        super().__init__(cfg)
        self._sem_per_host = asyncio.Semaphore(max(1, self.cfg.per_host_port_concurrency))

    async def _scan_port(self, ip: str, port: int) -> Optional[Service]:
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.cfg.connect_timeout_s)
        except Exception:
            return None

        banner = None
        is_tls = None
        svc_name = None

        try:
            if self.cfg.banner_enabled:
                # Minimalistic banner attempt for common services
                if port in (80, 8080, 8000, 8443):
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                    await writer.drain()
                elif port in (22,):
                    # SSH usually sends banner first; just read
                    pass
                elif port in (25, 110, 143):
                    pass
                try:
                    data = await asyncio.wait_for(reader.read(256), timeout=self.cfg.banner_read_timeout_s)
                    if data:
                        banner = data.decode(errors="ignore").strip()
                        # Heuristic service name
                        if "ssh" in banner.lower():
                            svc_name = "ssh"
                        elif "http" in banner.lower():
                            svc_name = "http"
                        elif "mysql" in banner.lower():
                            svc_name = "mysql"
                        elif "postgres" in banner.lower() or "postgresql" in banner.lower():
                            svc_name = "postgresql"
                        elif "redis" in banner.lower():
                            svc_name = "redis"
                        elif "mongodb" in banner.lower():
                            svc_name = "mongodb"
                except Exception:
                    banner = banner or None
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        return Service(port=port, proto="tcp", banner=banner, service=svc_name, tls=is_tls)

    async def run(self, ip: str) -> ProbeResult:
        services: List[Service] = []

        async def _guarded(port: int) -> None:
            async with self._sem_per_host:
                svc = await self._scan_port(ip, port)
                if svc:
                    services.append(svc)

        tasks = [asyncio.create_task(_guarded(p)) for p in sorted(set(self.cfg.ports))]
        if not tasks:
            return ProbeResult(alive=False, services=[], sources={"tcp"})
        await asyncio.gather(*tasks, return_exceptions=True)
        return ProbeResult(alive=len(services) > 0, services=services, sources={"tcp"})

class SNMPProbe(BaseProbe):
    name = "snmp"

    async def run(self, ip: str) -> ProbeResult:
        pr = ProbeResult(alive=False, sources=set())
        if not self.cfg.snmp_enabled or not _snmp_available:
            return pr
        try:
            # Try communities in order, first successful wins
            for community in self.cfg.snmp_communities:
                res = await self._snmp_try(ip, community)
                if res:
                    pr.alive = True
                    pr.sources.add("snmp")
                    pr.hostname = res.get("sysName")
                    # OS guess from sysDescr
                    pr.os_guess = res.get("sysDescr")
                    break
        except Exception:
            # Silent failure; SNMP often filtered
            pass
        return pr

    async def _snmp_try(self, ip: str, community: str) -> Optional[Dict[str, str]]:
        assert snmp is not None  # type: ignore
        engine = snmp.SnmpEngine()
        target = snmp.UdpTransportTarget((ip, self.cfg.snmp_port), timeout=self.cfg.snmp_timeout_s, retries=0)
        community_data = snmp.CommunityData(community, mpModel=0)
        # sysName(1.3.6.1.2.1.1.5.0), sysDescr(1.3.6.1.2.1.1.1.0)
        oids = [snmp.ObjectType(snmp.ObjectIdentity("1.3.6.1.2.1.1.5.0")),
                snmp.ObjectType(snmp.ObjectIdentity("1.3.6.1.2.1.1.1.0"))]
        result: Dict[str, str] = {}
        try:
            errorIndication, errorStatus, errorIndex, varBinds = await snmp.getCmd(
                engine, community_data, target, snmp.ContextData(), *oids
            )
            if errorIndication or errorStatus:
                return None
            for vb in varBinds:
                oid, val = vb
                s = str(oid)
                if s.endswith(".5.0"):
                    result["sysName"] = str(val)
                elif s.endswith(".1.0"):
                    result["sysDescr"] = str(val)
            return result if result else None
        finally:
            try:
                await engine.transportDispatcher.closeDispatcher()  # type: ignore
            except Exception:
                pass

class SSDPProbe(BaseProbe):
    name = "ssdp"

    async def run(self, _: str) -> ProbeResult:
        """SSDP is broadcast-based; not per-host. Handled by engine separately."""
        return ProbeResult(alive=False, sources=set())

    async def broadcast(self) -> Dict[str, str]:
        """
        Send M-SEARCH to discover UPnP devices; return map ip->server header or location.
        """
        results: Dict[str, str] = {}
        msg = "\r\n".join([
            "M-SEARCH * HTTP/1.1",
            "HOST: 239.255.255.250:1900",
            'MAN: "ssdp:discover"',
            f"MX: {max(1, self.cfg.ssdp_mx)}",
            "ST: ssdp:all",
            "", ""
        ]).encode()

        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(self.cfg.ssdp_timeout_s)
            sock.sendto(msg, ("239.255.255.250", 1900))

            end = time.monotonic() + self.cfg.ssdp_timeout_s
            while time.monotonic() < end:
                try:
                    data, addr = await loop.run_in_executor(None, sock.recvfrom, 2048)
                    txt = data.decode(errors="ignore")
                    ip = addr[0]
                    server = None
                    m = re.search(r"(?i)^server:\s*(.+)$", txt, re.M)
                    if m:
                        server = m.group(1).strip()
                    elif (m := re.search(r"(?i)^location:\s*(.+)$", txt, re.M)):
                        server = m.group(1).strip()
                    if ip not in results:
                        results[ip] = server or "ssdp-device"
                except (socket.timeout, TimeoutError):
                    break
                except Exception:
                    break
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return results

# --- Engine -------------------------------------------------------------------
TAsset = TypeVar("TAsset", bound=Asset)

class DiscoveryEngine:
    """
    Orchestrates multi-probe discovery across targets with concurrency & rate limiting.
    """

    def __init__(self, cfg: Optional[DiscoveryConfig] = None) -> None:
        self.cfg = cfg or DiscoveryConfig()
        self._global_sem = asyncio.Semaphore(max(1, self.cfg.global_host_concurrency))
        self._rl = TokenBucket(rate_per_sec=self.cfg.rate_limit_per_sec, burst=self.cfg.rate_burst)
        self._ping = PingProbe(self.cfg)
        self._tcp = TCPConnectProbe(self.cfg)
        self._snmp = SNMPProbe(self.cfg)
        self._ssdp = SSDPProbe(self.cfg) if self.cfg.ssdp_enabled else None
        self.correlation_id = self.cfg.correlation_id or str(uuid.uuid4())
        self._tracing = _tracer is not None

    def _log(self, level: int, msg: str, **extra: Any) -> None:
        extra = {"correlation_id": self.correlation_id, **extra}
        logger.log(level, f"{msg} | extra={json.dumps(extra, ensure_ascii=False)}")

    # Public API ---------------------------------------------------------------
    async def discover(self, targets: Sequence[str]) -> DiscoveryReport:
        started = time.monotonic()
        t0 = now_utc()

        # Normalize targets (CIDR or IPs) with safety cap
        ips = self._expand_targets(targets)
        if len(ips) > self.cfg.max_targets:
            ips = ips[: self.cfg.max_targets]
            self._log(logging.WARNING, "Targets truncated by max_targets", truncated=len(ips))

        self._log(logging.INFO, "Discovery started", targets=len(ips))

        # SSDP broadcast (if enabled) happens once per run
        ssdp_found: Dict[str, str] = {}
        if self._ssdp:
            ssdp_found = await self._ssdp.broadcast()
            self._log(logging.INFO, "SSDP broadcast complete", devices=len(ssdp_found))

        assets: Dict[str, Asset] = {}

        async def _process_ip(ip: str) -> None:
            async with self._global_sem:
                await self._rl.acquire()
                try:
                    await self._discover_host(ip, assets, ssdp_found.get(ip))
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    self._log(logging.WARNING, "Host discovery failed", ip=ip, error=str(e))

        # Tracing span (optional)
        span_ctx = _tracer.start_as_current_span("asset_discovery") if _tracer else None
        if span_ctx:  # pragma: no cover
            span_ctx.__enter__()
        try:
            tasks = [asyncio.create_task(_process_ip(ip)) for ip in ips]
            # Run with backpressure
            for chunk in _chunks(tasks, 2048):
                await asyncio.gather(*chunk, return_exceptions=True)
        finally:
            if span_ctx:  # pragma: no cover
                span_ctx.__exit__(None, None, None)

        alive = sum(1 for a in assets.values() if a.alive)
        finished = time.monotonic()
        t1 = now_utc()
        report = DiscoveryReport(
            started_at=t0,
            finished_at=t1,
            duration_s=finished - started,
            scanned_targets=len(ips),
            alive_hosts=alive,
            assets=list(assets.values()),
        )
        self._log(logging.INFO, "Discovery finished", scanned=len(ips), alive=alive, duration_s=report.duration_s)
        return report

    async def iter_assets(self, targets: Sequence[str]) -> AsyncIterator[Asset]:
        """Async iterator yielding assets as they are discovered."""
        # We build a small cache to avoid duplicates in streaming mode.
        seen: Set[str] = set()
        ips = self._expand_targets(targets)
        if len(ips) > self.cfg.max_targets:
            ips = ips[: self.cfg.max_targets]
        ssdp_found: Dict[str, str] = {}
        if self._ssdp:
            ssdp_found = await self._ssdp.broadcast()

        async def _process_ip(ip: str):
            async with self._global_sem:
                await self._rl.acquire()
                asset = await self._discover_host(ip, None, ssdp_found.get(ip))
                return asset

        tasks = [asyncio.create_task(_process_ip(ip)) for ip in ips]
        for fut in asyncio.as_completed(tasks):
            try:
                asset = await fut
                if not asset:
                    continue
                if asset.ip not in seen:
                    seen.add(asset.ip)
                    yield asset
            except Exception as e:
                self._log(logging.WARNING, "iter_assets host failed", error=str(e))

    # Internal -----------------------------------------------------------------
    def _expand_targets(self, targets: Sequence[str]) -> List[str]:
        ips: List[str] = []
        for t in targets:
            t = t.strip()
            if not t:
                continue
            try:
                if "/" in t:
                    net = ipaddress.ip_network(t, strict=False)
                    # Skip network/broadcast for IPv4
                    if isinstance(net, ipaddress.IPv4Network):
                        ips.extend([str(ip) for ip in net.hosts()])
                    else:
                        # For IPv6, host listing is enormous; take a sample of gateway-like addresses
                        sample = [net.network_address + 1, net.network_address + 2, net.network_address + 0xFF]
                        ips.extend([str(ip) for ip in sample if ip in net])
                else:
                    # Single IP or hostname resolved to IP
                    try:
                        ipaddress.ip_address(t)
                        ips.append(t)
                    except ValueError:
                        resolved = socket.gethostbyname(t)
                        ips.append(resolved)
            except Exception:
                self._log(logging.WARNING, "Target parse failed", target=t)
        # De-dup, preserve order
        dedup: List[str] = []
        seen: Set[str] = set()
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                dedup.append(ip)
        return dedup

    async def _discover_host(self, ip: str, aggregate: Optional[Dict[str, Asset]], ssdp_hint: Optional[str]) -> Optional[Asset]:
        # Run ICMP first (fast reachability)
        ping_res = await self._ping.run(ip)
        alive = ping_res.alive

        # If ICMP fails, we may still try TCP (some networks block ICMP)
        tcp_res: Optional[ProbeResult] = None
        if alive:
            tcp_res = await self._tcp.run(ip)
        else:
            # Try limited TCP to confirm liveness
            limited_ports = list({80, 443, 22} & set(self.cfg.ports))
            if limited_ports:
                saved_ports = self.cfg.ports
                try:
                    self.cfg.ports = limited_ports
                    tcp_res = await self._tcp.run(ip)
                finally:
                    self.cfg.ports = saved_ports

        # Aggregate basic fields
        asset = Asset(ip=ip)
        asset.alive = bool(ping_res.alive or (tcp_res and tcp_res.alive))
        asset.sources.extend(sorted(set(ping_res.sources | (tcp_res.sources if tcp_res else set()))))
        asset.last_seen = now_utc()

        # Hostname/MAC
        asset.hostname = ping_res.hostname or None
        asset.mac = ping_res.mac or None

        # TCP services
        if tcp_res and tcp_res.services:
            asset.services.extend(sorted(tcp_res.services, key=lambda s: (s.proto, s.port)))

        # SNMP enrichment
        if self.cfg.snmp_enabled and _snmp_available:
            snmp_res = await self._snmp.run(ip)
            if snmp_res.alive:
                asset.sources.append("snmp")
                asset.hostname = asset.hostname or snmp_res.hostname
                asset.os_guess = asset.os_guess or snmp_res.os_guess
                asset.alive = True

        # SSDP hint (broadcast-discovered device)
        if ssdp_hint:
            if "ssdp" not in asset.sources:
                asset.sources.append("ssdp")
            if not asset.hostname:
                # Often SSDP 'SERVER' header exposes device type; keep as tag
                asset.tags.append("ssdp")
            # Store hint as pseudo-banner on port 1900
            asset.services.append(Service(port=1900, proto="udp", banner=ssdp_hint, service="ssdp", tls=None))

        # Optionally attempt reverse DNS if not set (second chance)
        if not asset.hostname and self.cfg.resolve_hostname and asset.alive:
            host = await _reverse_dns(ip, timeout_s=0.8)
            if host:
                asset.hostname = host

        # Merge to aggregate dict if provided
        if aggregate is not None:
            prev = aggregate.get(ip)
            if prev is None:
                aggregate[ip] = asset
            else:
                aggregate[ip] = _merge_assets(prev, asset)

        return asset

# --- Merge logic --------------------------------------------------------------
def _merge_assets(a: Asset, b: Asset) -> Asset:
    out = Asset(**a.dict())
    out.alive = a.alive or b.alive
    out.hostname = a.hostname or b.hostname
    out.mac = a.mac or b.mac
    out.vendor = a.vendor or b.vendor
    out.os_guess = a.os_guess or b.os_guess
    # Merge services by (proto,port)
    svc_map: Dict[Tuple[str, int], Service] = {(s.proto, s.port): s for s in a.services}
    for s in b.services:
        key = (s.proto, s.port)
        if key not in svc_map:
            svc_map[key] = s
        else:
            # Merge banners favoring non-empty
            base = svc_map[key]
            if not base.banner and s.banner:
                base.banner = s.banner
            if base.service is None and s.service:
                base.service = s.service
            if base.tls is None and s.tls is not None:
                base.tls = s.tls
    out.services = sorted(svc_map.values(), key=lambda s: (s.proto, s.port))
    # Merge sources/tags
    out.sources = sorted(set(a.sources) | set(b.sources))
    out.tags = sorted(set(a.tags) | set(b.tags))
    # Update last_seen to the most recent
    out.last_seen = max(a.last_seen, b.last_seen)
    return out

# --- Helpers ------------------------------------------------------------------
def _chunks(seq: Sequence[Any], size: int) -> Iterable[Sequence[Any]]:
    for i in range(0, len(seq), size):
        yield seq[i : i + size]

# --- Public convenience function ---------------------------------------------
async def run_discovery(
    targets: Sequence[str],
    cfg: Optional[DiscoveryConfig] = None,
) -> DiscoveryReport:
    """
    Convenience wrapper to run discovery end-to-end and return a report.
    """
    engine = DiscoveryEngine(cfg)
    return await engine.discover(targets)

# --- __all__ ------------------------------------------------------------------
__all__ = [
    "Service",
    "Asset",
    "DiscoveryConfig",
    "DiscoveryReport",
    "DiscoveryEngine",
    "run_discovery",
]
