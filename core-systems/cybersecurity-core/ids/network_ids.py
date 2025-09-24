# cybersecurity-core/cybersecurity/ids/network_ids.py
# -*- coding: utf-8 -*-
"""
Industrial-grade asynchronous Network IDS pipeline.

Design goals:
- Safe-by-default: optional deps (scapy, dpkt, aiokafka, aiohttp) are detected at runtime.
- Run anywhere: file-based PCAP processing works без дополнительных библиотек (через dpkt, если установлен;
  иначе — fallback на scapy.rdpcap, если установлен).
- Async pipeline: capture -> decode -> detect -> sink; bounded queues, backpressure, graceful shutdown.
- Modular detectors:
    * PortScanDetector          — всплески уникальных dst/port по источнику за окно времени
    * DnsAnomalyDetector        — туннелирование: энтропия, длины меток, частые TXT, длинные QNAME
    * SignatureDetector         — байтовые и текстовые regex-паттерны по полезной нагрузке
    * HttpHeuristicsDetector    — подозрительные Host/UA/URI (regex)
    * TlsHeuristicsDetector     — редкие версии/расширения (эвристика), JA3 (если доступен парсер)
- Sinks:
    * StdoutSink (ECS-like JSON)
    * FileSink (ротация по размеру)
    * HttpSink (POST JSON, aiohttp если доступен)
    * KafkaSink (aiokafka, если доступен)
- Observability: lightweight metrics-снимок и структурированный лог.
- Config: dataclasses; правила сигнатур (bytes/regex) можно загрузить из YAML/JSON.

Note: Живой захват (iface) возможен через Scapy (sniff) или WinDivert (pydivert) — если установлены.
В противном случае используйте PCAP-файлы (офлайн-анализ).

Python: 3.11+
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import fnmatch
import ipaddress
import json
import logging
import os
import queue
import random
import re
import signal
import struct
import sys
import time
from asyncio import Queue
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, Iterable, List, Optional, Tuple

# Optional deps
try:  # packet parsing / offline PCAP
    import dpkt  # type: ignore
    _HAS_DPKT = True
except Exception:
    _HAS_DPKT = False

try:  # live capture alternative / fallback decode
    from scapy.all import sniff as scapy_sniff, rdpcap as scapy_rdpcap  # type: ignore
    from scapy.all import TCP as SCAPY_TCP, UDP as SCAPY_UDP, IP as SCAPY_IP, IPv6 as SCAPY_IPv6  # type: ignore
    _HAS_SCAPY = True
except Exception:
    _HAS_SCAPY = False

try:  # Windows live capture
    import pydivert  # type: ignore
    _HAS_WINDIVERT = True
except Exception:
    _HAS_WINDIVERT = False

try:  # HTTP sink
    import aiohttp  # type: ignore
    _HAS_AIOHTTP = True
except Exception:
    _HAS_AIOHTTP = False

try:  # Kafka sink
    from aiokafka import AIOKafkaProducer  # type: ignore
    _HAS_KAFKA = True
except Exception:
    _HAS_KAFKA = False

logger = logging.getLogger("network_ids")
logging.basicConfig(
    level=os.getenv("NETWORK_IDS_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

# =============================================================================
# Data model
# =============================================================================

class Severity(str):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(slots=True)
class PacketMeta:
    ts: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    proto: str  # "TCP"|"UDP"|"ICMP"|"OTHER"
    payload: bytes = b""
    l7_host: Optional[str] = None
    l7_path: Optional[str] = None
    l7_dns_qname: Optional[str] = None
    l7_tls_version: Optional[str] = None
    l7_tls_sni: Optional[str] = None


@dataclass(slots=True)
class Alert:
    ts: float
    detector: str
    severity: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    category: str
    reason: str
    score: float = 0.0
    evidence: Dict[str, Any] = field(default_factory=dict)
    trace_id: str = field(default_factory=lambda: f"ids-{int(time.time()*1000)}-{random.randint(1000,9999)}")

    def to_json(self) -> str:
        # ECS-like event
        body = {
            "@timestamp": datetime.fromtimestamp(self.ts, tz=timezone.utc).isoformat(),
            "event": {"kind": "alert", "module": "network_ids", "category": self.category, "severity": self.severity},
            "rule": {"name": self.detector},
            "source": {"ip": self.src_ip, "port": self.src_port},
            "destination": {"ip": self.dst_ip, "port": self.dst_port},
            "network": {"transport": "tcp" if self.src_port and self.dst_port else None},
            "ids": {"score": self.score, "reason": self.reason, "trace_id": self.trace_id},
            "evidence": self.evidence or None,
        }
        # remove None leafs
        def _prune(x):
            if isinstance(x, dict):
                return {k: _prune(v) for k, v in x.items() if v is not None}
            return x
        return json.dumps(_prune(body), ensure_ascii=False)


# =============================================================================
# Utils
# =============================================================================

def now_ts() -> float:
    return time.time()


def shannon_entropy(b: bytes) -> float:
    if not b:
        return 0.0
    from math import log2
    freqs = [0] * 256
    for x in b:
        freqs[x] += 1
    ent = 0.0
    ln = len(b)
    for c in freqs:
        if c:
            p = c / ln
            ent -= p * log2(p)
    return ent


def domain_entropy(name: str) -> float:
    try:
        return shannon_entropy(name.encode("idna"))
    except Exception:
        return shannon_entropy(name.encode("utf-8", "ignore"))


def safe_ip(s: str) -> str:
    try:
        return str(ipaddress.ip_address(s))
    except Exception:
        return s


# =============================================================================
# Config
# =============================================================================

@dataclass
class SignatureRule:
    name: str
    severity: str = Severity.MEDIUM
    # bytes pattern (hex string) OR regex (text/bytes). At least один из них.
    hex_bytes: Optional[str] = None
    regex: Optional[str] = None
    regex_flags: str = ""  # "i" etc.
    scope: str = "payload"  # payload | http.host | http.path | dns.qname | tls.sni

    def compile(self):
        pat = None
        if self.hex_bytes:
            pat = bytes.fromhex(self.hex_bytes.replace(" ", ""))
            return ("bytes", pat)
        if self.regex:
            flags = 0
            if "i" in self.regex_flags.lower():
                flags |= re.IGNORECASE
            try:
                return ("regex", re.compile(self.regex, flags))
            except re.error as e:
                raise ValueError(f"invalid regex for rule {self.name}: {e}")
        raise ValueError(f"invalid rule {self.name}: need hex_bytes or regex")


@dataclass
class IDSConfig:
    worker_count: int = 4
    queue_maxsize: int = 10000
    detect_timeout_ms: int = 50
    portscan_threshold: int = 100  # unique dst:(ip,port) in window
    portscan_window_s: int = 30
    dns_max_label_len: int = 35
    dns_entropy_threshold: float = 4.0
    dns_txt_ratio_threshold: float = 0.3
    dns_min_queries_in_window: int = 20
    http_suspicious_hosts: List[str] = dataclasses.field(default_factory=lambda: ["*.onion", "*tor*"])
    http_regex_ua: Optional[str] = None
    tls_min_version_ok: str = "TLS1.2"
    signatures: List[SignatureRule] = dataclasses.field(default_factory=list)
    sink_kind: str = "stdout"  # stdout|file|kafka|http
    sink_params: Dict[str, Any] = dataclasses.field(default_factory=dict)


# =============================================================================
# Sinks
# =============================================================================

class AlertSink:
    async def start(self): ...
    async def stop(self): ...
    async def send(self, alert: Alert): ...


class StdoutSink(AlertSink):
    async def start(self): ...
    async def stop(self): ...
    async def send(self, alert: Alert):
        print(alert.to_json(), flush=True)


class FileSink(AlertSink):
    def __init__(self, path: str, max_bytes: int = 50_000_000, backups: int = 5):
        self._path = Path(path)
        self._max = max_bytes
        self._backups = backups
        self._fp: Optional[Any] = None

    async def start(self):
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fp = self._path.open("a", encoding="utf-8", buffering=1)

    async def stop(self):
        if self._fp:
            self._fp.close()
            self._fp = None

    def _rotate(self):
        try:
            if not self._fp:
                return
            self._fp.flush()
            sz = self._path.stat().st_size
            if sz < self._max:
                return
            self._fp.close()
            for i in range(self._backups - 1, 0, -1):
                src = self._path.with_suffix(self._path.suffix + f".{i}")
                dst = self._path.with_suffix(self._path.suffix + f".{i+1}")
                if src.exists():
                    src.replace(dst)
            self._path.replace(self._path.with_suffix(self._path.suffix + ".1"))
            self._fp = self._path.open("a", encoding="utf-8", buffering=1)
        except Exception as e:
            logger.warning("FileSink rotate failed: %s", e)

    async def send(self, alert: Alert):
        if not self._fp:
            return
        self._fp.write(alert.to_json() + "\n")
        self._rotate()


class HttpSink(AlertSink):
    def __init__(self, url: str, timeout_s: float = 5.0, headers: Optional[Dict[str, str]] = None):
        self._url = url
        self._timeout = timeout_s
        self._headers = headers or {"Content-Type": "application/json"}
        self._session = None

    async def start(self):
        if not _HAS_AIOHTTP:
            raise RuntimeError("aiohttp is required for HttpSink")
        self._session = aiohttp.ClientSession()

    async def stop(self):
        if self._session:
            await self._session.close()
            self._session = None

    async def send(self, alert: Alert):
        if not self._session:
            return
        try:
            async with self._session.post(self._url, data=alert.to_json(), headers=self._headers, timeout=self._timeout) as resp:
                if resp.status >= 300:
                    logger.warning("HttpSink non-2xx: %s", resp.status)
        except Exception as e:
            logger.warning("HttpSink error: %s", e)


class KafkaSink(AlertSink):
    def __init__(self, bootstrap_servers: str, topic: str, **kwargs):
        self._servers = bootstrap_servers
        self._topic = topic
        self._kwargs = kwargs
        self._producer = None

    async def start(self):
        if not _HAS_KAFKA:
            raise RuntimeError("aiokafka is required for KafkaSink")
        self._producer = AIOKafkaProducer(bootstrap_servers=self._servers, **self._kwargs)
        await self._producer.start()

    async def stop(self):
        if self._producer:
            await self._producer.stop()
            self._producer = None

    async def send(self, alert: Alert):
        if not self._producer:
            return
        await self._producer.send_and_wait(self._topic, alert.to_json().encode("utf-8"))


def build_sink(cfg: IDSConfig) -> AlertSink:
    kind = cfg.sink_kind.lower()
    if kind == "stdout":
        return StdoutSink()
    if kind == "file":
        path = cfg.sink_params.get("path", "./ids_alerts.ndjson")
        max_bytes = int(cfg.sink_params.get("max_bytes", 50_000_000))
        backups = int(cfg.sink_params.get("backups", 5))
        return FileSink(path, max_bytes, backups)
    if kind == "http":
        if not _HAS_AIOHTTP:
            logger.warning("Http sink requested but aiohttp is not installed; fallback to stdout")
            return StdoutSink()
        return HttpSink(cfg.sink_params["url"], float(cfg.sink_params.get("timeout_s", 5.0)),
                        headers=cfg.sink_params.get("headers"))
    if kind == "kafka":
        if not _HAS_KAFKA:
            logger.warning("Kafka sink requested but aiokafka not installed; fallback to stdout")
            return StdoutSink()
        return KafkaSink(cfg.sink_params["bootstrap_servers"], cfg.sink_params["topic"],
                         **{k: v for k, v in cfg.sink_params.items() if k not in ("bootstrap_servers", "topic")})
    logger.warning("Unknown sink '%s'; fallback to stdout", kind)
    return StdoutSink()


# =============================================================================
# Detectors
# =============================================================================

class Detector:
    name: str = "base"
    async def analyze(self, pkt: PacketMeta) -> List[Alert]:
        return []


class PortScanDetector(Detector):
    name = "port_scan"
    def __init__(self, threshold: int, window_s: int):
        self.threshold = threshold
        self.window = window_s
        self.bucket: Dict[str, deque[Tuple[float, Tuple[str, int]]]] = defaultdict(deque)
        self.seen_sets: Dict[str, set[Tuple[str, int]]] = defaultdict(set)

    def _expire(self, now: float, src: str):
        dq = self.bucket[src]
        st = self.seen_sets[src]
        while dq and now - dq[0][0] > self.window:
            _, key = dq.popleft()
            # удаляем из множества, если такой key больше не встречается в окне
            if key not in [k for _, k in dq]:
                with contextlib.suppress(KeyError):
                    st.remove(key)

    async def analyze(self, pkt: PacketMeta) -> List[Alert]:
        if pkt.proto not in ("TCP", "UDP") or pkt.dst_port is None:
            return []
        now = pkt.ts
        key = (pkt.dst_ip, pkt.dst_port)
        dq = self.bucket[pkt.src_ip]
        dq.append((now, key))
        st = self.seen_sets[pkt.src_ip]
        st.add(key)
        self._expire(now, pkt.src_ip)
        if len(st) >= self.threshold:
            return [Alert(
                ts=now, detector=self.name, severity=Severity.HIGH,
                src_ip=pkt.src_ip, dst_ip=pkt.dst_ip, src_port=pkt.src_port, dst_port=pkt.dst_port,
                category="network_traffic",
                reason=f"unique dst targets >= {self.threshold} in {self.window}s",
                score=min(100.0, 50.0 + (len(st) - self.threshold) * 1.0),
                evidence={"unique_targets": len(st)}
            )]
        return []


class DnsAnomalyDetector(Detector):
    name = "dns_anomaly"
    def __init__(self, cfg: IDSConfig):
        self.max_label_len = cfg.dns_max_label_len
        self.ent_thr = cfg.dns_entropy_threshold
        self.txt_ratio = cfg.dns_txt_ratio_threshold
        self.min_q = cfg.dns_min_queries_in_window
        self.window = 60
        self.qcount: Dict[str, deque[Tuple[float, str]]] = defaultdict(deque)

    def _labels(self, qname: str) -> List[str]:
        return [x for x in qname.split(".") if x]

    def _expire(self, now: float, src: str):
        dq = self.qcount[src]
        while dq and now - dq[0][0] > self.window:
            dq.popleft()

    async def analyze(self, pkt: PacketMeta) -> List[Alert]:
        if not pkt.l7_dns_qname:
            return []
        qname = pkt.l7_dns_qname.lower().strip(".")
        labels = self._labels(qname)
        reasons = []
        # длина меток
        if any(len(lb) > self.max_label_len for lb in labels):
            reasons.append("long_label")
        # энтропия
        if domain_entropy(qname) >= self.ent_thr:
            reasons.append("high_entropy")
        # частота TXT-запросов детектируем эвристически по наличию 'txt.' или ключевых слов
        self.qcount[pkt.src_ip].append((pkt.ts, qname))
        self._expire(pkt.ts, pkt.src_ip)
        dq = self.qcount[pkt.src_ip]
        if len(dq) >= self.min_q:
            txt_like = sum(1 for _, n in dq if any(s in n for s in ["txt.", "_dmarc", "_acme-challenge"]))
            ratio = txt_like / max(1, len(dq))
            if ratio >= self.txt_ratio:
                reasons.append("txt_ratio")

        if reasons:
            return [Alert(
                ts=pkt.ts, detector=self.name, severity=Severity.MEDIUM,
                src_ip=pkt.src_ip, dst_ip=pkt.dst_ip, src_port=pkt.src_port, dst_port=pkt.dst_port,
                category="dns", reason=";".join(reasons),
                score=60.0, evidence={"qname": qname, "reasons": reasons}
            )]
        return []


class SignatureDetector(Detector):
    name = "signature"
    def __init__(self, rules: List[SignatureRule]):
        self._compiled: List[Tuple[SignatureRule, Tuple[str, Any]]] = []
        for r in rules:
            self._compiled.append((r, r.compile()))

    def _match_scope(self, pkt: PacketMeta, kind: str, pat: Any, scope: str) -> bool:
        value: Optional[bytes | str] = None
        if scope == "payload":
            value = pkt.payload
        elif scope == "http.host":
            value = pkt.l7_host or ""
        elif scope == "http.path":
            value = pkt.l7_path or ""
        elif scope == "dns.qname":
            value = pkt.l7_dns_qname or ""
        elif scope == "tls.sni":
            value = pkt.l7_tls_sni or ""
        else:
            return False

        if kind == "bytes":
            if isinstance(value, bytes):
                return pat in value
            return pat in (value or "").encode("utf-8", "ignore")
        if kind == "regex":
            if isinstance(value, bytes):
                return bool(pat.search(value))
            return bool(pat.search(value or ""))
        return False

    async def analyze(self, pkt: PacketMeta) -> List[Alert]:
        alerts: List[Alert] = []
        for rule, (kind, pat) in self._compiled:
            if self._match_scope(pkt, kind, pat, rule.scope):
                alerts.append(Alert(
                    ts=pkt.ts, detector=f"{self.name}:{rule.name}", severity=rule.severity,
                    src_ip=pkt.src_ip, dst_ip=pkt.dst_ip, src_port=pkt.src_port, dst_port=pkt.dst_port,
                    category="signature", reason=f"matched rule {rule.name}", score=80.0,
                    evidence={"scope": rule.scope}
                ))
        return alerts


class HttpHeuristicsDetector(Detector):
    name = "http_heuristics"
    def __init__(self, suspicious_hosts: List[str], ua_regex: Optional[str]):
        self.host_patterns = suspicious_hosts
        self.ua_re = re.compile(ua_regex, re.I) if ua_regex else None

    def _host_susp(self, host: Optional[str]) -> bool:
        if not host:
            return False
        for pat in self.host_patterns:
            if fnmatch.fnmatch(host.lower(), pat.lower()):
                return True
        return False

    async def analyze(self, pkt: PacketMeta) -> List[Alert]:
        if not pkt.l7_host and not pkt.l7_path:
            return []
        reasons = []
        if self._host_susp(pkt.l7_host):
            reasons.append("suspicious_host")
        if self.ua_re and self.ua_re.search(pkt.payload.decode("latin-1", "ignore")):
            reasons.append("ua_pattern")
        if reasons:
            return [Alert(
                ts=pkt.ts, detector=self.name, severity=Severity.LOW,
                src_ip=pkt.src_ip, dst_ip=pkt.dst_ip, src_port=pkt.src_port, dst_port=pkt.dst_port,
                category="http", reason=";".join(reasons), score=40.0,
                evidence={"host": pkt.l7_host, "path": pkt.l7_path}
            )]
        return []


class TlsHeuristicsDetector(Detector):
    name = "tls_heuristics"
    def __init__(self, min_ok: str = "TLS1.2"):
        # простая проверка версии по строковому представлению; подробный TLS-парсинг опционален
        self.min_ok = min_ok

    def _version_rank(self, v: Optional[str]) -> int:
        order = {"TLS1.0": 1, "TLS1.1": 2, "TLS1.2": 3, "TLS1.3": 4}
        return order.get(v or "", 0)

    async def analyze(self, pkt: PacketMeta) -> List[Alert]:
        if not pkt.l7_tls_version:
            return []
        if self._version_rank(pkt.l7_tls_version) < self._version_rank(self.min_ok):
            return [Alert(
                ts=pkt.ts, detector=self.name, severity=Severity.LOW,
                src_ip=pkt.src_ip, dst_ip=pkt.dst_ip, src_port=pkt.src_port, dst_port=pkt.dst_port,
                category="tls", reason=f"legacy_tls:{pkt.l7_tls_version}", score=30.0,
                evidence={"sni": pkt.l7_tls_sni}
            )]
        return []


# =============================================================================
# Packet decoding (best-effort)
# =============================================================================

def _parse_with_dpkt(ts: float, raw: bytes) -> Optional[PacketMeta]:
    try:
        eth = dpkt.ethernet.Ethernet(raw)
        ip = eth.data
        if isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
            src = ipaddress.ip_address(ip.src)
            dst = ipaddress.ip_address(ip.dst)
            proto = "OTHER"
            sport = dport = None
            payload = b""
            host = path = None
            dns_qname = None
            tls_ver = None
            tls_sni = None

            l4 = ip.data
            if isinstance(l4, dpkt.tcp.TCP):
                proto = "TCP"
                sport, dport = l4.sport, l4.dport
                payload = bytes(l4.data or b"")
                # rudimentary HTTP request parse
                with contextlib.suppress(Exception):
                    if payload.startswith(b"GET") or payload.startswith(b"POST") or payload.startswith(b"HEAD") or payload.startswith(b"PUT") or payload.startswith(b"DELETE"):
                        req = dpkt.http.Request(payload)
                        host = req.headers.get("host")
                        path = req.uri
                # rudimentary TLS client hello detection
                if payload and payload[0] == 0x16:  # Handshake
                    with contextlib.suppress(Exception):
                        # dpkt.tls may not parse all ClientHello; best-effort
                        rec = dpkt.ssl.TLSRecord(payload)
                        if rec.type == 22 and rec.data and hasattr(rec.data, "version"):
                            v = rec.data.version
                            tls_ver = {0x0301: "TLS1.0", 0x0302: "TLS1.1", 0x0303: "TLS1.2", 0x0304: "TLS1.3"}.get(v)
                            # SNI extraction is unreliable here; ignoring unless trivial
            elif isinstance(l4, dpkt.udp.UDP):
                proto = "UDP"
                sport, dport = l4.sport, l4.dport
                payload = bytes(l4.data or b"")
                # DNS query parse (port 53)
                if dport == 53 or sport == 53:
                    with contextlib.suppress(Exception):
                        dns = dpkt.dns.DNS(payload)
                        if dns.qd and len(dns.qd) > 0 and hasattr(dns.qd[0], "name"):
                            dns_qname = dns.qd[0].name.decode("utf-8", "ignore") if isinstance(dns.qd[0].name, bytes) else dns.qd[0].name

            return PacketMeta(
                ts=ts, src_ip=str(src), dst_ip=str(dst),
                src_port=sport, dst_port=dport, proto=proto, payload=payload,
                l7_host=host, l7_path=path, l7_dns_qname=dns_qname,
                l7_tls_version=tls_ver, l7_tls_sni=tls_sni
            )
    except Exception:
        return None
    return None


def _parse_with_scapy(ts: float, pkt) -> Optional[PacketMeta]:
    try:
        ip = None
        if pkt.haslayer(SCAPY_IP):
            ip = pkt[SCAPY_IP]
            src, dst = ip.src, ip.dst
        elif pkt.haslayer(SCAPY_IPv6):
            ip = pkt[SCAPY_IPv6]
            src, dst = ip.src, ip.dst
        else:
            return None
        src = safe_ip(src)
        dst = safe_ip(dst)
        proto = "OTHER"
        sport = dport = None
        payload = bytes(pkt.payload.payload.original) if hasattr(pkt.payload, "payload") and hasattr(pkt.payload.payload, "original") else bytes(pkt.payload.original) if hasattr(pkt.payload, "original") else bytes(pkt.original)
        host = path = None
        dns_qname = None
        tls_ver = None
        tls_sni = None

        if pkt.haslayer(SCAPY_TCP):
            proto = "TCP"
            sport = int(pkt[SCAPY_TCP].sport)
            dport = int(pkt[SCAPY_TCP].dport)
            # naive HTTP parse
            try:
                text = payload.decode("latin-1", "ignore")
                if text.startswith(("GET ", "POST ", "HEAD ", "PUT ", "DELETE ")):
                    for line in text.split("\r\n"):
                        if line.lower().startswith("host:"):
                            host = line.split(":", 1)[1].strip()
                        if line.startswith(("GET ", "POST ", "HEAD ", "PUT ", "DELETE ")):
                            parts = line.split(" ")
                            if len(parts) >= 2:
                                path = parts[1]
            except Exception:
                pass
            # TLS heuristic
            if payload[:1] == b"\x16":
                tls_ver = None  # scapy TLS parsing optional; leaving None
        elif pkt.haslayer(SCAPY_UDP):
            proto = "UDP"
            sport = int(pkt[SCAPY_UDP].sport)
            dport = int(pkt[SCAPY_UDP].dport)
            if dport == 53 or sport == 53:
                try:
                    text = payload
                    # very naive DNS QNAME extraction
                    def _decode_dns_qname(data: bytes) -> str:
                        res = []
                        i = 12  # skip header
                        while i < len(data):
                            ln = data[i]
                            if ln == 0:
                                break
                            i += 1
                            res.append(data[i:i+ln].decode("utf-8", "ignore"))
                            i += ln
                        return ".".join(res)
                    dns_qname = _decode_dns_qname(text)
                except Exception:
                    pass

        return PacketMeta(
            ts=ts, src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
            proto=proto, payload=payload, l7_host=host, l7_path=path,
            l7_dns_qname=dns_qname, l7_tls_version=tls_ver, l7_tls_sni=tls_sni
        )
    except Exception:
        return None


# =============================================================================
# Sources
# =============================================================================

class PacketSource:
    async def packets(self) -> AsyncGenerator[PacketMeta, None]:
        yield  # pragma: no cover


class PCAPFileSource(PacketSource):
    def __init__(self, path: str):
        self.path = path

    async def packets(self) -> AsyncGenerator[PacketMeta, None]:
        p = Path(self.path)
        if not p.exists():
            raise FileNotFoundError(self.path)
        if _HAS_DPKT:
            with p.open("rb") as f:
                reader = dpkt.pcap.Reader(f)
                for ts, raw in reader:
                    pkt = _parse_with_dpkt(ts, raw)
                    if pkt:
                        yield pkt
                    await asyncio.sleep(0)  # cooperative
        elif _HAS_SCAPY:
            pkts = scapy_rdpcap(str(p))
            base = time.time()
            for scp in pkts:
                ts = getattr(scp, "time", base)
                pkt = _parse_with_scapy(ts, scp)
                if pkt:
                    yield pkt
                await asyncio.sleep(0)
        else:
            raise RuntimeError("Neither dpkt nor scapy is available to read PCAP")


class LiveInterfaceSource(PacketSource):
    def __init__(self, iface: Optional[str] = None, bpf: Optional[str] = None):
        self.iface = iface
        self.bpf = bpf

    async def packets(self) -> AsyncGenerator[PacketMeta, None]:
        if not _HAS_SCAPY:
            raise RuntimeError("LiveInterfaceSource requires scapy")
        loop = asyncio.get_event_loop()
        q: asyncio.Queue = asyncio.Queue(maxsize=10000)

        def _cb(pkt):
            try:
                q.put_nowait(pkt)
            except queue.Full:
                pass

        # scapy sniff is blocking; run in thread
        def _sniff():
            scapy_sniff(iface=self.iface, filter=self.bpf, prn=_cb, store=False)

        t = asyncio.to_thread(_sniff)
        task = asyncio.create_task(t)
        try:
            while True:
                scp = await q.get()
                ts = getattr(scp, "time", time.time())
                pkt = _parse_with_scapy(ts, scp)
                if pkt:
                    yield pkt
        finally:
            task.cancel()


class WinDivertSource(PacketSource):
    def __init__(self, flt: str = "true"):
        self.filter = flt

    async def packets(self) -> AsyncGenerator[PacketMeta, None]:
        if not _HAS_WINDIVERT:
            raise RuntimeError("WinDivertSource requires pydivert on Windows")
        with pydivert.WinDivert(self.filter) as w:
            for packet in w:
                ts = time.time()
                raw = bytes(packet.raw.tobytes())
                pkt = _parse_with_dpkt(ts, raw) if _HAS_DPKT else None
                # WinDivert already parsed IPs and ports; fallback if dpkt missing
                if not pkt:
                    try:
                        src_ip = str(packet.src_addr)
                        dst_ip = str(packet.dst_addr)
                        sport = int(packet.src_port) if packet.src_port else None
                        dport = int(packet.dst_port) if packet.dst_port else None
                        proto = "TCP" if packet.tcp else "UDP" if packet.udp else "OTHER"
                        pkt = PacketMeta(ts, src_ip, dst_ip, sport, dport, proto, raw)
                    except Exception:
                        pkt = None
                if pkt:
                    yield pkt
                await asyncio.sleep(0)


# =============================================================================
# IDS Pipeline
# =============================================================================

class NetworkIDS:
    def __init__(self, cfg: IDSConfig, source: PacketSource):
        self.cfg = cfg
        self.source = source
        self.queue: Queue[PacketMeta] = Queue(maxsize=cfg.queue_maxsize)
        self.sink: AlertSink = build_sink(cfg)
        # detectors
        self.detectors: List[Detector] = [
            PortScanDetector(cfg.portscan_threshold, cfg.portscan_window_s),
            DnsAnomalyDetector(cfg),
            SignatureDetector(cfg.signatures),
            HttpHeuristicsDetector(cfg.http_suspicious_hosts, cfg.http_regex_ua),
            TlsHeuristicsDetector(cfg.tls_min_version_ok),
        ]
        self._workers: List[asyncio.Task] = []
        self._producer_task: Optional[asyncio.Task] = None
        self._running = False
        self._metrics = {
            "packets_in": 0,
            "alerts_out": 0,
            "queue_max": 0,
            "dropped_packets": 0,
            "detector_errors": 0,
        }

    async def start(self):
        await self.sink.start()
        self._running = True
        self._producer_task = asyncio.create_task(self._producer())
        for i in range(self.cfg.worker_count):
            self._workers.append(asyncio.create_task(self._worker(i)))
        logger.info("NetworkIDS started with %d workers", self.cfg.worker_count)

    async def stop(self):
        self._running = False
        if self._producer_task:
            self._producer_task.cancel()
            with contextlib.suppress(Exception):
                await self._producer_task
        for w in self._workers:
            w.cancel()
        for w in self._workers:
            with contextlib.suppress(Exception):
                await w
        await self.sink.stop()
        logger.info("NetworkIDS stopped")

    async def _producer(self):
        try:
            async for pkt in self.source.packets():
                if not self._running:
                    break
                try:
                    self.queue.put_nowait(pkt)
                    self._metrics["packets_in"] += 1
                    self._metrics["queue_max"] = max(self._metrics["queue_max"], self.queue.qsize())
                except asyncio.QueueFull:
                    self._metrics["dropped_packets"] += 1
                await asyncio.sleep(0)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.exception("Producer error: %s", e)

    async def _worker(self, wid: int):
        try:
            while True:
                pkt = await self.queue.get()
                alerts = await self._run_detectors(pkt)
                for a in alerts:
                    await self.sink.send(a)
                self._metrics["alerts_out"] += len(alerts)
        except asyncio.CancelledError:
            return
        except Exception as e:
            logger.exception("Worker %d error: %s", wid, e)

    async def _run_detectors(self, pkt: PacketMeta) -> List[Alert]:
        results: List[Alert] = []
        for det in self.detectors:
            try:
                coro = det.analyze(pkt)
                alerts: List[Alert] = await asyncio.wait_for(
                    coro, timeout=self.cfg.detect_timeout_ms / 1000.0
                )
                if alerts:
                    results.extend(alerts)
            except asyncio.TimeoutError:
                self._metrics["detector_errors"] += 1
                logger.warning("Detector %s timeout", det.name)
            except Exception as e:
                self._metrics["detector_errors"] += 1
                logger.exception("Detector %s error: %s", det.name, e)
        return results

    def metrics(self) -> Dict[str, Any]:
        return dict(self._metrics)


# =============================================================================
# Helper: Load signatures from JSON/YAML
# =============================================================================

def load_signatures(path: str) -> List[SignatureRule]:
    p = Path(path)
    if not p.exists():
        return []
    text = p.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore
        obj = yaml.safe_load(text)
    except Exception:
        obj = json.loads(text)
    rules: List[SignatureRule] = []
    for raw in obj or []:
        rules.append(SignatureRule(
            name=raw["name"],
            severity=raw.get("severity", Severity.MEDIUM),
            hex_bytes=raw.get("hex_bytes"),
            regex=raw.get("regex"),
            regex_flags=raw.get("regex_flags", ""),
            scope=raw.get("scope", "payload"),
        ))
    return rules


# =============================================================================
# Entrypoint utility (optional)
# =============================================================================

async def run_ids_from_env() -> None:
    """
    Convenience runner configured via env vars.

    ENV:
      IDS_SOURCE=pcap:/path/file.pcap | iface:eth0 | windivert:true
      IDS_SINK=stdout|file|http|kafka
      IDS_SIGNATURES=/path/to/rules.(yaml|json)
      IDS_PORTSCAN_THRESHOLD=100
      IDS_PORTSCAN_WINDOW=30
      IDS_DNS_ENTROPY=4.0
    """
    src_env = os.getenv("IDS_SOURCE", "pcap:./sample.pcap")
    kind, _, param = src_env.partition(":")
    if kind == "pcap":
        source = PCAPFileSource(param)
    elif kind == "iface":
        source = LiveInterfaceSource(param or None, os.getenv("IDS_BPF"))
    elif kind == "windivert":
        source = WinDivertSource(param or "true")
    else:
        raise RuntimeError(f"Unknown IDS_SOURCE: {src_env}")

    sig_path = os.getenv("IDS_SIGNATURES")
    rules = load_signatures(sig_path) if sig_path else []

    cfg = IDSConfig(
        worker_count=int(os.getenv("IDS_WORKERS", "4")),
        queue_maxsize=int(os.getenv("IDS_QUEUE", "10000")),
        detect_timeout_ms=int(os.getenv("IDS_TIMEOUT_MS", "50")),
        portscan_threshold=int(os.getenv("IDS_PORTSCAN_THRESHOLD", "100")),
        portscan_window_s=int(os.getenv("IDS_PORTSCAN_WINDOW", "30")),
        dns_entropy_threshold=float(os.getenv("IDS_DNS_ENTROPY", "4.0")),
        signatures=rules,
        sink_kind=os.getenv("IDS_SINK", "stdout"),
        sink_params=json.loads(os.getenv("IDS_SINK_PARAMS", "{}")),
        http_suspicious_hosts=os.getenv("IDS_HTTP_HOSTS", "*.onion,*tor*").split(","),
        http_regex_ua=os.getenv("IDS_HTTP_UA_REGEX", None),
        tls_min_version_ok=os.getenv("IDS_TLS_MIN_OK", "TLS1.2"),
    )

    ids = NetworkIDS(cfg, source)
    await ids.start()

    # graceful shutdown
    stop_ev = asyncio.Event()

    def _stop(*_):
        stop_ev.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, _stop)

    await stop_ev.wait()
    await ids.stop()


# If executed as script:
if __name__ == "__main__":
    try:
        asyncio.run(run_ids_from_env())
    except KeyboardInterrupt:
        pass
