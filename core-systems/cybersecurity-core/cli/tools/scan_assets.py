#!/usr/bin/env python3
# cybersecurity-core/cli/tools/scan_assets.py
# -*- coding: utf-8 -*-
from __future__ import annotations

"""
Industrial-grade async asset scanner.

Features
--------
- Async DNS resolution and TCP reachability checks
- Optional lightweight HTTP probe (HEAD /) with banner capture
- Optional TLS certificate metadata (subject, issuer, notBefore/notAfter, SNI)
- CIDR and target list expansion, flexible port syntax (e.g. "80,443,8080-8090")
- Concurrency control via semaphore, global per-connection timeouts
- Exponential backoff retries with jitter
- Structured logging (JSON-ready) with log levels
- Deterministic JSONL and CSV outputs
- Graceful shutdown on Ctrl+C (SIGINT/SIGTERM), partial results preserved
- Zero external deps (standard library only)

Usage
-----
python scan_assets.py \
  --targets 192.168.1.0/30,example.org --ports 80,443,22 \
  --concurrency 200 --timeout 3.0 \
  --enable-http --enable-tls \
  --jsonl out/results.jsonl --csv out/results.csv --log-level INFO

Notes
-----
- Designed for internal, authorized security testing. Ensure you have permission.
"""

import argparse
import asyncio
import csv
import ipaddress
import json
import logging
import os
import random
import signal
import socket
import ssl
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Iterable, List, Optional, Sequence, Tuple

APP_NAME = "scan_assets"
APP_VERSION = "1.0.0"

# ----------------------------- Logging ------------------------------------- #

def setup_logging(level: str) -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=lvl,
        format='{"ts":"%(asctime)s","level":"%(levelname)s",'
               '"msg":"%(message)s","module":"%(module)s","line":%(lineno)d}',
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

logger = logging.getLogger(__name__)

# ----------------------------- Data models --------------------------------- #

@dataclass(frozen=True)
class Target:
    host: str               # original host or ip
    ip: str                 # resolved ip (IPv4/IPv6 textual)
    port: int
    sni: Optional[str] = None  # for TLS probes, hostname if available

@dataclass
class TCPProbe:
    reachable: bool = False
    latency_ms: Optional[float] = None
    banner: Optional[str] = None
    error: Optional[str] = None

@dataclass
class HTTPProbe:
    status: Optional[int] = None
    server: Optional[str] = None
    title: Optional[str] = None
    location: Optional[str] = None
    error: Optional[str] = None

@dataclass
class TLSCertInfo:
    subject: Optional[str] = None
    issuer: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    san: Optional[List[str]] = None
    error: Optional[str] = None

@dataclass
class ScanResult:
    ts: str
    host: str
    ip: str
    port: int
    tcp: TCPProbe = field(default_factory=TCPProbe)
    http: Optional[HTTPProbe] = None
    tls: Optional[TLSCertInfo] = None
    error: Optional[str] = None
    retries: int = 0

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True)

# ----------------------------- Utilities ----------------------------------- #

def parse_ports(spec: str) -> List[int]:
    """
    Parse port spec like "80,443,8080-8090" into sorted unique int list.
    """
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            a, b = chunk.split("-", 1)
            start, end = int(a), int(b)
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {chunk}")
            ports.update(range(start, end + 1))
        else:
            p = int(chunk)
            if p < 1 or p > 65535:
                raise ValueError(f"Invalid port: {chunk}")
            ports.add(p)
    return sorted(ports)

def load_targets(arg: str | None, targets_list: Sequence[str] | None) -> List[str]:
    """
    Load raw targets from CLI input (file or comma-separated) or list.
    Accepts hostnames, IPs, CIDR notations. Returns unique strings.
    """
    raw: List[str] = []
    if arg:
        if os.path.isfile(arg):
            with open(arg, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        raw.append(line)
        else:
            raw.extend([x.strip() for x in arg.split(",") if x.strip()])
    if targets_list:
        for t in targets_list:
            t = t.strip()
            if t:
                raw.append(t)
    # deduplicate preserving order
    seen = set()
    unique = []
    for t in raw:
        if t not in seen:
            unique.append(t)
            seen.add(t)
    if not unique:
        raise ValueError("No targets provided")
    return unique

def expand_targets(raw_targets: Sequence[str]) -> List[Tuple[str, Optional[str]]]:
    """
    Expand CIDR ranges into individual IPs.
    Returns list of (item, sni_host_if_hostname_else_None).
    """
    expanded: List[Tuple[str, Optional[str]]] = []
    for item in raw_targets:
        try:
            network = ipaddress.ip_network(item, strict=False)
            for ip in network.hosts() if hasattr(network, "hosts") else [network]:
                expanded.append((str(ip), None))
        except ValueError:
            # Not a CIDR/IP -> hostname or single IP string
            try:
                ipaddress.ip_address(item)
                expanded.append((item, None))
            except ValueError:
                # hostname
                expanded.append((item, item))
    return expanded

async def resolve_host(loop: asyncio.AbstractEventLoop, host: str) -> List[str]:
    """
    Resolve host to list of IP addresses (both A and AAAA).
    """
    ips: set[str] = set()
    try:
        # family=0 lets the resolver return both AF_INET and AF_INET6 if available
        infos = await loop.getaddrinfo(host, None, family=0, type=socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in infos:
            if family == socket.AF_INET:
                ips.add(sockaddr[0])
            elif family == socket.AF_INET6:
                ips.add(sockaddr[0])
    except Exception as e:
        logger.debug(f"DNS resolve failed for {host}: {e}")
    return sorted(ips)

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# ----------------------------- Probes -------------------------------------- #

async def tcp_probe(ip: str, port: int, timeout: float) -> TCPProbe:
    start = time.perf_counter()
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    try:
        conn = asyncio.open_connection(ip, port)  # type: ignore[call-arg]
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        latency = (time.perf_counter() - start) * 1000.0
        banner: Optional[str] = None

        # Try to grab minimal banner for common ports without sending payload
        # SSH often sends its banner first; HTTP might respond to HEAD later in http_probe.
        if port in (22, 25, 110, 143):  # SSH/SMTP/POP3/IMAP (best-effort, non-blocking)
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=0.5)
                if line:
                    banner = line.decode(errors="ignore").strip()
            except asyncio.TimeoutError:
                pass

        return TCPProbe(reachable=True, latency_ms=round(latency, 2), banner=banner)
    except Exception as e:
        latency = (time.perf_counter() - start) * 1000.0
        return TCPProbe(reachable=False, latency_ms=round(latency, 2), error=repr(e))
    finally:
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

async def http_probe(host: str, ip: str, port: int, timeout: float) -> HTTPProbe:
    """
    Very small HTTP HEAD request over raw asyncio streams (no aiohttp dependency).
    """
    # Compose request to target IP but include Host header with original hostname if available
    request = (
        f"HEAD / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {APP_NAME}/{APP_VERSION}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.write(request)
        await writer.drain()

        # Read up to 64KB to capture headers and maybe a bit of body
        raw = await asyncio.wait_for(reader.read(65536), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        text = raw.decode(errors="ignore", encoding="utf-8",)
        # Parse minimal headers
        status = None
        server = None
        location = None
        title = None

        lines = text.split("\r\n")
        if lines and lines[0].startswith("HTTP/"):
            try:
                status = int(lines[0].split()[1])
            except Exception:
                status = None
        for line in lines[1:]:
            if not line:
                break
            lower = line.lower()
            if lower.startswith("server:"):
                server = line.split(":", 1)[1].strip() or None
            elif lower.startswith("location:"):
                location = line.split(":", 1)[1].strip() or None

        # Try to extract <title> if body accidentally included
        if "<title>" in text.lower():
            try:
                lo = text.lower().find("<title>")
                hi = text.lower().find("</title>", lo + 7)
                if lo != -1 and hi != -1:
                    title = text[lo + 7 : hi].strip()
            except Exception:
                title = None

        return HTTPProbe(status=status, server=server, title=title, location=location)
    except Exception as e:
        return HTTPProbe(error=repr(e))

async def tls_probe(hostname: str, ip: str, port: int, timeout: float) -> TLSCertInfo:
    """
    Establish minimal TLS handshake to retrieve certificate using stdlib ssl.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # metadata only; no trust validation here

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=hostname),
            timeout=timeout,
        )
        # getpeercert returns a dict when not requesting binary_form
        sslobj = writer.get_extra_info("ssl_object")
        cert_dict = sslobj.getpeercert() if sslobj else None
        cert = TLSCertInfo()
        if cert_dict:
            # subject/issuer are sequences of tuples like ((('commonName','example.com'),),)
            def _name_to_str(name_seq) -> Optional[str]:
                try:
                    parts = []
                    for rdn in name_seq:
                        for k, v in rdn:
                            parts.append(f"{k}={v}")
                    return ", ".join(parts) if parts else None
                except Exception:
                    return None

            cert.subject = _name_to_str(cert_dict.get("subject", ()))
            cert.issuer = _name_to_str(cert_dict.get("issuer", ()))
            not_before = cert_dict.get("notBefore")
            not_after = cert_dict.get("notAfter")
            cert.not_before = not_before
            cert.not_after = not_after

            san = []
            for t, v in cert_dict.get("subjectAltName", ()):
                san.append(f"{t}:{v}")
            cert.san = san or None

        # Close connection
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        return cert
    except Exception as e:
        return TLSCertInfo(error=repr(e))

# -------------------------- Orchestrator ----------------------------------- #

class Scanner:
    def __init__(
        self,
        ports: Sequence[int],
        concurrency: int,
        timeout: float,
        retries: int,
        jitter: float,
        enable_http: bool,
        enable_tls: bool,
    ) -> None:
        self.ports = list(ports)
        self.sem = asyncio.Semaphore(concurrency)
        self.timeout = timeout
        self.retries = retries
        self.jitter = jitter
        self.enable_http = enable_http
        self.enable_tls = enable_tls
        self._stop = asyncio.Event()

    def stop(self) -> None:
        self._stop.set()

    async def build_targets(self, raw_targets: Sequence[str]) -> List[Target]:
        loop = asyncio.get_running_loop()
        expanded = expand_targets(raw_targets)
        out: List[Target] = []

        async def resolve_one(item: Tuple[str, Optional[str]]) -> List[Target]:
            token, sni = item
            # If token is hostname -> resolve to IPs; else token is IP
            try:
                ipaddress.ip_address(token)
                ips = [token]
            except ValueError:
                ips = await resolve_host(loop, token)
            tgts: List[Target] = []
            for ip in ips:
                for p in self.ports:
                    tgts.append(Target(host=token, ip=ip, port=p, sni=sni))
            return tgts

        tasks = [resolve_one(it) for it in expanded]
        for sub in await asyncio.gather(*tasks):
            out.extend(sub)

        # Deduplicate by (ip, port, host)
        uniq = {(t.ip, t.port, t.host): t for t in out}
        results = list(uniq.values())
        results.sort(key=lambda t: (t.ip, t.port))
        logger.info(f"Prepared {len(results)} targets to scan")
        return results

    async def _with_retries(self, coro_fn, *args, **kwargs):
        last_exc = None
        for attempt in range(self.retries + 1):
            if self._stop.is_set():
                raise asyncio.CancelledError()
            try:
                return await coro_fn(*args, **kwargs)
            except asyncio.TimeoutError as e:
                last_exc = e
            except Exception as e:
                last_exc = e
            if attempt < self.retries:
                delay = min(1.0 * (2**attempt), 5.0)
                if self.jitter:
                    delay += random.uniform(0, self.jitter)
                await asyncio.sleep(delay)
        raise last_exc if last_exc else RuntimeError("Retry loop exhausted")

    async def scan_one(self, tgt: Target) -> ScanResult:
        async with self.sem:
            if self._stop.is_set():
                raise asyncio.CancelledError()
            res = ScanResult(ts=now_iso(), host=tgt.host, ip=tgt.ip, port=tgt.port)
            try:
                tcp: TCPProbe = await self._with_retries(
                    tcp_probe, tgt.ip, tgt.port, self.timeout
                )
                res.tcp = tcp
                if not tcp.reachable:
                    return res

                if self.enable_http and tgt.port in (80, 8080, 8000, 443, 8443):
                    # For HTTPS ports, HTTP without TLS may fail; that's ok.
                    http: HTTPProbe = await self._with_retries(
                        http_probe, tgt.sni or tgt.host or tgt.ip, tgt.ip, tgt.port, self.timeout
                    )
                    res.http = http

                if self.enable_tls and tgt.port in (443, 8443, 993, 995, 465, 587, 4433, 9443):
                    if tgt.sni:
                        tlsinfo: TLSCertInfo = await self._with_retries(
                            tls_probe, tgt.sni, tgt.ip, tgt.port, self.timeout
                        )
                        res.tls = tlsinfo
            except asyncio.CancelledError:
                res.error = "cancelled"
                raise
            except Exception as e:
                res.error = repr(e)
            finally:
                return res

    async def run(self, targets: Sequence[str], writer: "ResultsWriter") -> None:
        tgts = await self.build_targets(targets)
        total = len(tgts)
        done = 0
        start = time.perf_counter()

        async def _task(t: Target) -> None:
            nonlocal done
            try:
                r = await self.scan_one(t)
                writer.write(r)
            except asyncio.CancelledError:
                pass
            finally:
                done += 1
                if done % 100 == 0 or done == total:
                    logger.info(f"Progress: {done}/{total}")

        tasks = [asyncio.create_task(_task(t)) for t in tgts]

        # Graceful shutdown
        def _handle_sig():
            logger.warning("Stop signal received, cancelling pending tasks…")
            self.stop()
            for tk in tasks:
                tk.cancel()

        loop = asyncio.get_running_loop()
        try:
            loop.add_signal_handler(signal.SIGINT, _handle_sig)
        except NotImplementedError:
            # Windows prior to Python 3.8 or limited environments
            pass
        try:
            loop.add_signal_handler(signal.SIGTERM, _handle_sig)
        except Exception:
            pass

        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            elapsed = time.perf_counter() - start
            logger.info(f"Finished {done}/{total} in {elapsed:.2f}s")

# ------------------------- Results writer ---------------------------------- #

class ResultsWriter:
    def __init__(self, jsonl_path: Optional[str], csv_path: Optional[str]) -> None:
        self.jsonl_path = jsonl_path
        self.csv_path = csv_path
        self._jsonl_file = None
        self._csv_file = None
        self._csv_writer: Optional[csv.DictWriter] = None

        if self.jsonl_path:
            os.makedirs(os.path.dirname(self.jsonl_path) or ".", exist_ok=True)
            self._jsonl_file = open(self.jsonl_path, "w", encoding="utf-8")

        if self.csv_path:
            os.makedirs(os.path.dirname(self.csv_path) or ".", exist_ok=True)
            self._csv_file = open(self.csv_path, "w", encoding="utf-8", newline="")
            # Define flat CSV header
            fieldnames = [
                "ts",
                "host",
                "ip",
                "port",
                "tcp_reachable",
                "tcp_latency_ms",
                "tcp_banner",
                "tcp_error",
                "http_status",
                "http_server",
                "http_title",
                "http_location",
                "http_error",
                "tls_subject",
                "tls_issuer",
                "tls_not_before",
                "tls_not_after",
                "tls_san",
                "tls_error",
                "error",
                "retries",
            ]
            self._csv_writer = csv.DictWriter(self._csv_file, fieldnames=fieldnames)
            self._csv_writer.writeheader()

    def write(self, result: ScanResult) -> None:
        # JSONL
        if self._jsonl_file:
            self._jsonl_file.write(result.to_json())
            self._jsonl_file.write("\n")
            self._jsonl_file.flush()

        # CSV
        if self._csv_writer:
            row = {
                "ts": result.ts,
                "host": result.host,
                "ip": result.ip,
                "port": result.port,
                "tcp_reachable": result.tcp.reachable,
                "tcp_latency_ms": result.tcp.latency_ms,
                "tcp_banner": result.tcp.banner,
                "tcp_error": result.tcp.error,
                "http_status": result.http.status if result.http else None,
                "http_server": result.http.server if result.http else None,
                "http_title": result.http.title if result.http else None,
                "http_location": result.http.location if result.http else None,
                "http_error": result.http.error if result.http else None,
                "tls_subject": result.tls.subject if result.tls else None,
                "tls_issuer": result.tls.issuer if result.tls else None,
                "tls_not_before": result.tls.not_before if result.tls else None,
                "tls_not_after": result.tls.not_after if result.tls else None,
                "tls_san": ";".join(result.tls.san) if (result.tls and result.tls.san) else None,
                "tls_error": result.tls.error if result.tls else None,
                "error": result.error,
                "retries": result.retries,
            }
            self._csv_writer.writerow(row)
            self._csv_file.flush()  # type: ignore[union-attr]

    def close(self) -> None:
        if self._jsonl_file:
            self._jsonl_file.close()
        if self._csv_file:
            self._csv_file.close()

# ----------------------------- CLI ----------------------------------------- #

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=APP_NAME,
        description="Asynchronous asset scanner (TCP/HTTP/TLS)"
    )
    p.add_argument(
        "--targets",
        type=str,
        default=None,
        help="Comma-separated targets or a file path. Supports hostname, IP, CIDR.",
    )
    p.add_argument(
        "--target",
        action="append",
        dest="targets_list",
        help="Repeatable single target (hostname/IP/CIDR)."
    )
    p.add_argument(
        "--ports",
        type=str,
        default="80,443,22",
        help="Port spec, e.g. '80,443,8080-8090'. Default: 80,443,22",
    )
    p.add_argument(
        "--concurrency",
        type=int,
        default=500,
        help="Max concurrent probes (default: 500)."
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Per-connection timeout seconds (default: 3.0).",
    )
    p.add_argument(
        "--retries",
        type=int,
        default=1,
        help="Number of retries on error/timeout (default: 1)."
    )
    p.add_argument(
        "--jitter",
        type=float,
        default=0.150,
        help="Random jitter added to backoff, seconds (default: 0.150)."
    )
    p.add_argument(
        "--enable-http",
        action="store_true",
        help="Enable HTTP HEAD banner probe on common web ports."
    )
    p.add_argument(
        "--enable-tls",
        action="store_true",
        help="Enable TLS metadata probe on typical TLS ports (uses SNI when hostname is known)."
    )
    p.add_argument(
        "--jsonl",
        type=str,
        default=None,
        help="Write JSONL results to this file."
    )
    p.add_argument(
        "--csv",
        type=str,
        default=None,
        help="Write CSV results to this file."
    )
    p.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        help="Logging level: DEBUG, INFO, WARNING, ERROR (default: INFO)."
    )
    p.add_argument(
        "--version",
        action="store_true",
        help="Print version and exit."
    )
    return p

async def main_async(args: argparse.Namespace) -> int:
    setup_logging(args.log_level)

    if args.version:
        print(f"{APP_NAME} {APP_VERSION}")
        return 0

    try:
        raw_targets = load_targets(args.targets, args.targets_list)
        ports = parse_ports(args.ports)
    except Exception as e:
        logger.error(f"Input error: {e}")
        return 2

    writer = ResultsWriter(jsonl_path=args.jsonl, csv_path=args.csv)

    scanner = Scanner(
        ports=ports,
        concurrency=max(1, args.concurrency),
        timeout=max(0.1, args.timeout),
        retries=max(0, args.retries),
        jitter=max(0.0, args.jitter),
        enable_http=bool(args.enable_http),
        enable_tls=bool(args.enable_tls),
    )

    exit_code = 0
    try:
        await scanner.run(raw_targets, writer)
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        exit_code = 130
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        exit_code = 1
    finally:
        writer.close()
    return exit_code

def main() -> None:
    parser = build_arg_parser()
    ns = parser.parse_args()
    try:
        asyncio.run(main_async(ns))
    except KeyboardInterrupt:
        sys.exit(130)

if __name__ == "__main__":
    main()
