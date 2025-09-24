# file: security-core/security/audit/exporters/siem_exporter.py
from __future__ import annotations

import asyncio
import gzip
import json
import logging
import os
import socket
import ssl
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import httpx  # optional, used if available
    _HAVE_HTTPX = True
except Exception:
    _HAVE_HTTPX = False

from pydantic import BaseModel, Field, validator

logger = logging.getLogger("security_core.audit.siem")

# =============================================================================
# Utilities
# =============================================================================

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _iso(dt: Optional[datetime] = None) -> str:
    return (dt or _now_utc()).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def _redact(s: Optional[str], keep: int = 4) -> str:
    if not s:
        return ""
    return s if len(s) <= 2 * keep else s[:keep] + "…" + s[-keep:]

def _to_bytes(data: Any) -> bytes:
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    if isinstance(data, str):
        return data.encode("utf-8")
    return json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

# =============================================================================
# Domain model
# =============================================================================

class Outcome(str):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENY = "DENY"
    ERROR = "ERROR"

class Severity(str):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

_SEV_TO_NUM = {
    "INFO": 3, "LOW": 4, "MEDIUM": 6, "HIGH": 8, "CRITICAL": 10
}

class AuditEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: str = Field(default_factory=_iso)  # RFC3339
    tenant_id: Optional[str] = None
    actor_id: Optional[str] = None
    actor_type: Optional[str] = None
    action: str
    target_type: Optional[str] = None
    target_id: Optional[str] = None
    source: Optional[str] = None
    ip: Optional[str] = None
    outcome: str = Field(default=Outcome.SUCCESS)
    severity: str = Field(default=Severity.INFO)
    risk_score: Optional[float] = None
    trace_id: Optional[str] = None
    session_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)

    @validator("severity")
    def _v_sev(cls, v: str) -> str:
        v = (v or "").upper()
        if v not in _SEV_TO_NUM:
            raise ValueError("invalid severity")
        return v

    @validator("outcome")
    def _v_out(cls, v: str) -> str:
        v = (v or "").upper()
        if v not in {Outcome.SUCCESS, Outcome.FAILURE, Outcome.DENY, Outcome.ERROR}:
            raise ValueError("invalid outcome")
        return v

# =============================================================================
# Circuit breaker
# =============================================================================

@dataclass
class CircuitBreaker:
    failure_threshold: int = 5
    recovery_timeout_sec: int = 30
    half_open_successes: int = 3

    state: str = "CLOSED"
    failures: int = 0
    opened_at: float = 0.0
    half_successes: int = 0

    def allow(self) -> bool:
        now = time.time()
        if self.state == "OPEN":
            if now - self.opened_at >= self.recovery_timeout_sec:
                self.state = "HALF_OPEN"
                self.half_successes = 0
                return True
            return False
        return True

    def on_success(self) -> None:
        if self.state == "HALF_OPEN":
            self.half_successes += 1
            if self.half_successes >= self.half_open_successes:
                self.state = "CLOSED"
                self.failures = 0
        else:
            self.failures = 0

    def on_failure(self) -> None:
        if self.state in ("CLOSED", "HALF_OPEN"):
            self.failures += 1
            if self.failures >= self.failure_threshold:
                self.state = "OPEN"
                self.opened_at = time.time()

# =============================================================================
# Exporter interface and result
# =============================================================================

@dataclass
class ExportResult:
    ok: bool
    sent: int
    failed: int
    error: Optional[str] = None

class Exporter:
    name: str

    async def start(self) -> None:
        return None

    async def export(self, batch: List[AuditEvent]) -> ExportResult:
        raise NotImplementedError

    async def aclose(self) -> None:
        return None

# =============================================================================
# Splunk HEC exporter
# =============================================================================

@dataclass
class SplunkHECConfig:
    url: str  # https://splunk.example.com:8088/services/collector
    token: str
    index: Optional[str] = None
    source: str = "security-core"
    sourcetype: str = "aethernova:audit"
    host: Optional[str] = None
    verify_ssl: bool = True
    timeout_sec: float = 5.0
    gzip_payload: bool = True
    max_attempts: int = 4
    backoff_base_ms: int = 200
    backoff_max_ms: int = 3000

class SplunkHECExporter(Exporter):
    def __init__(self, cfg: SplunkHECConfig):
        self.cfg = cfg
        self.name = "splunk_hec"
        self._cb = CircuitBreaker()
        self._client = None

    async def start(self) -> None:
        if _HAVE_HTTPX:
            self._client = httpx.AsyncClient(verify=self.cfg.verify_ssl, timeout=self.cfg.timeout_sec)

    async def aclose(self) -> None:
        if self._client:
            await self._client.aclose()

    def _wrap_event(self, e: AuditEvent) -> Dict[str, Any]:
        return {
            "time": datetime.fromisoformat(e.timestamp.replace("Z", "+00:00")).timestamp(),
            "host": self.cfg.host,
            "source": self.cfg.source,
            "sourcetype": self.cfg.sourcetype,
            "index": self.cfg.index,
            "event": e.dict(),
        }

    async def export(self, batch: List[AuditEvent]) -> ExportResult:
        if not batch:
            return ExportResult(ok=True, sent=0, failed=0)

        if not self._cb.allow():
            return ExportResult(ok=False, sent=0, failed=len(batch), error="circuit_open")

        lines = [_to_bytes(json.dumps(self._wrap_event(e), separators=(",", ":"), ensure_ascii=False)) for e in batch]
        payload = b"\n".join(lines)
        headers = {
            "Authorization": f"Splunk {self.cfg.token}",
            "Content-Type": "application/json",
            "User-Agent": "aethernova-security-core/siem-exporter",
        }

        if self.cfg.gzip_payload:
            payload = gzip.compress(payload)
            headers["Content-Encoding"] = "gzip"

        # Send with retries
        attempt = 0
        backoff = self.cfg.backoff_base_ms
        while True:
            attempt += 1
            try:
                if _HAVE_HTTPX:
                    assert self._client is not None
                    r = await self._client.post(self.cfg.url, content=payload, headers=headers)
                    if r.status_code // 100 != 2:
                        raise RuntimeError(f"HTTP {r.status_code} {r.text[:128]}")
                else:
                    # stdlib fallback
                    import urllib.request
                    req = urllib.request.Request(self.cfg.url, data=payload, method="POST", headers=headers)  # type: ignore
                    with urllib.request.urlopen(req, timeout=self.cfg.timeout_sec) as resp:  # type: ignore
                        if resp.status // 100 != 2:  # type: ignore
                            raise RuntimeError(f"HTTP {resp.status}")  # type: ignore
                self._cb.on_success()
                return ExportResult(ok=True, sent=len(batch), failed=0)
            except Exception as e:
                self._cb.on_failure()
                if attempt >= self.cfg.max_attempts:
                    logger.error("splunk.hec.export.fail", extra={"err": str(e)[:200]})
                    return ExportResult(ok=False, sent=0, failed=len(batch), error=str(e)[:200])
                await asyncio.sleep(min(backoff, self.cfg.backoff_max_ms) / 1000.0)
                backoff = min(backoff * 2, self.cfg.backoff_max_ms)

# =============================================================================
# Elasticsearch Bulk exporter
# =============================================================================

@dataclass
class ElasticBulkConfig:
    url: str  # https://es.example.com:9200
    index_prefix: str = "security-core-audit"
    index_date_pattern: str = "%Y.%m.%d"
    pipeline: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    timeout_sec: float = 5.0
    verify_ssl: bool = True
    gzip_payload: bool = True
    max_attempts: int = 4
    backoff_base_ms: int = 200
    backoff_max_ms: int = 3000

class ElasticBulkExporter(Exporter):
    def __init__(self, cfg: ElasticBulkConfig):
        self.cfg = cfg
        self.name = "elastic_bulk"
        self._cb = CircuitBreaker()
        self._client = None
        self._bulk_url = self._mk_bulk_url()

    def _mk_bulk_url(self) -> str:
        path = "/_bulk"
        if self.cfg.pipeline:
            path += f"?pipeline={self.cfg.pipeline}"
        return self.cfg.url.rstrip("/") + path

    async def start(self) -> None:
        if _HAVE_HTTPX:
            auth = None
            if self.cfg.username and self.cfg.password:
                auth = (self.cfg.username, self.cfg.password)
            self._client = httpx.AsyncClient(verify=self.cfg.verify_ssl, timeout=self.cfg.timeout_sec, auth=auth)

    async def aclose(self) -> None:
        if self._client:
            await self._client.aclose()

    def _index_name(self, dt_iso: str) -> str:
        dt = datetime.fromisoformat(dt_iso.replace("Z", "+00:00"))
        return f"{self.cfg.index_prefix}-{dt.strftime(self.cfg.index_date_pattern)}"

    def _build_bulk(self, batch: List[AuditEvent]) -> bytes:
        lines = []
        for e in batch:
            idx = {"index": {"_index": self._index_name(e.timestamp), "_id": e.event_id}}
            lines.append(json.dumps(idx, separators=(",", ":"), ensure_ascii=False))
            lines.append(json.dumps(e.dict(), separators=(",", ":"), ensure_ascii=False))
        body = ("\n".join(lines) + "\n").encode("utf-8")
        return gzip.compress(body) if self.cfg.gzip_payload else body

    async def export(self, batch: List[AuditEvent]) -> ExportResult:
        if not batch:
            return ExportResult(ok=True, sent=0, failed=0)
        if not self._cb.allow():
            return ExportResult(ok=False, sent=0, failed=len(batch), error="circuit_open")

        payload = self._build_bulk(batch)
        headers = {
            "Content-Type": "application/x-ndjson",
            "User-Agent": "aethernova-security-core/siem-exporter",
        }
        if self.cfg.gzip_payload:
            headers["Content-Encoding"] = "gzip"

        attempt, backoff = 0, self.cfg.backoff_base_ms
        while True:
            attempt += 1
            try:
                if _HAVE_HTTPX:
                    assert self._client is not None
                    r = await self._client.post(self._bulk_url, content=payload, headers=headers)
                    if r.status_code // 100 != 2:
                        raise RuntimeError(f"HTTP {r.status_code} {r.text[:128]}")
                    data = r.json()
                else:
                    import urllib.request, base64
                    req = urllib.request.Request(self._bulk_url, data=payload, method="POST", headers=headers)  # type: ignore
                    if self.cfg.username and self.cfg.password:
                        token = base64.b64encode(f"{self.cfg.username}:{self.cfg.password}".encode()).decode()
                        req.add_header("Authorization", f"Basic {token}")
                    with urllib.request.urlopen(req, timeout=self.cfg.timeout_sec) as resp:  # type: ignore
                        if resp.status // 100 != 2:  # type: ignore
                            raise RuntimeError(f"HTTP {resp.status}")  # type: ignore
                        data = json.loads(resp.read().decode("utf-8"))  # type: ignore
                # Parse bulk response
                errors = 0
                if data.get("errors"):
                    for item in data.get("items", []):
                        st = item.get("index", {}).get("status", 200)
                        if st >= 300:
                            errors += 1
                if errors:
                    raise RuntimeError(f"bulk errors: {errors}")
                self._cb.on_success()
                return ExportResult(ok=True, sent=len(batch), failed=0)
            except Exception as e:
                self._cb.on_failure()
                if attempt >= self.cfg.max_attempts:
                    logger.error("elastic.bulk.export.fail", extra={"err": str(e)[:200]})
                    return ExportResult(ok=False, sent=0, failed=len(batch), error=str(e)[:200])
                await asyncio.sleep(min(backoff, self.cfg.backoff_max_ms) / 1000.0)
                backoff = min(backoff * 2, self.cfg.backoff_max_ms)

# =============================================================================
# Syslog CEF exporter
# =============================================================================

@dataclass
class SyslogCEFConfig:
    host: str
    port: int = 514
    protocol: str = "udp"  # "udp" | "tcp" | "tcp+tls"
    tls_verify: bool = True
    app_vendor: str = "Aethernova"
    app_product: str = "SecurityCore"
    app_version: str = "1.0"
    facility: int = 1  # user-level
    timeout_sec: float = 5.0
    max_attempts: int = 3
    backoff_base_ms: int = 150
    backoff_max_ms: int = 2000

class SyslogCEFExporter(Exporter):
    def __init__(self, cfg: SyslogCEFConfig):
        self.cfg = cfg
        self.name = "syslog_cef"
        self._cb = CircuitBreaker()
        self._sock: Optional[socket.socket] = None
        self._ssl_ctx: Optional[ssl.SSLContext] = None

    async def start(self) -> None:
        if self.cfg.protocol == "udp":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.cfg.timeout_sec)
            self._sock = s
        else:
            raw = socket.create_connection((self.cfg.host, self.cfg.port), timeout=self.cfg.timeout_sec)
            if self.cfg.protocol == "tcp+tls":
                ctx = ssl.create_default_context()
                if not self.cfg.tls_verify:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                self._ssl_ctx = ctx
                self._sock = ctx.wrap_socket(raw, server_hostname=self.cfg.host if self.cfg.tls_verify else None)
            else:
                self._sock = raw

    async def aclose(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def _cef(self, e: AuditEvent) -> str:
        # CEF:Version|Device Vendor|Device Product|Device Version|Signature|Name|Severity| Extension
        sev = _SEV_TO_NUM.get(e.severity, 3)
        sig = e.action
        name = f"{e.action} {e.outcome}"
        ext = {
            "end": _iso(e.timestamp),
            "rt": e.timestamp,
            "act": e.action,
            "suid": e.actor_id or "-",
            "requestClientApplication": e.source or "security-core",
            "cs1Label": "tenantId", "cs1": e.tenant_id or "-",
            "cs2Label": "traceId", "cs2": e.trace_id or "-",
            "cs3Label": "sessionId", "cs3": e.session_id or "-",
            "dst": e.target_id or "-",
            "dpriv": e.target_type or "-",
            "src": e.ip or "-",
            "outcome": e.outcome,
            "cn1Label": "riskScore", "cn1": int((e.risk_score or 0) * 100),
            "deviceCustomDate1Label": "eventTime", "deviceCustomDate1": e.timestamp,
            "msg": json.dumps(e.attributes, separators=(",", ":"), ensure_ascii=False) if e.attributes else "-",
        }
        # Escape per CEF
        def esc(v: Any) -> str:
            s = str(v)
            return s.replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=")
        ext_str = " ".join([f"{k}={esc(v)}" for k, v in ext.items()])
        header = f"CEF:0|{self.cfg.app_vendor}|{self.cfg.app_product}|{self.cfg.app_version}|{esc(sig)}|{esc(name)}|{sev}|"
        return header + " " + ext_str

    async def export(self, batch: List[AuditEvent]) -> ExportResult:
        if not batch:
            return ExportResult(ok=True, sent=0, failed=0)
        if not self._cb.allow():
            return ExportResult(ok=False, sent=0, failed=len(batch), error="circuit_open")
        if not self._sock:
            await self.start()

        # Syslog framing RFC 5424 with CEF in MSG
        HOSTNAME = socket.gethostname()
        APPNAME = "security-core"
        PROCID = "-"
        MSGID = "audit"
        PRI = self.cfg.facility * 8 + 6  # facility + severity info
        sent, failed = 0, 0

        attempt, backoff = 0, self.cfg.backoff_base_ms
        data: List[bytes] = []
        for e in batch:
            ts = datetime.fromisoformat(e.timestamp.replace("Z", "+00:00")).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            cef = self._cef(e)
            syslog = f"<{PRI}>1 {ts} {HOSTNAME} {APPNAME} {PROCID} {MSGID} - {cef}"
            # If TCP, add octet-counting framing. If UDP, raw.
            if self.cfg.protocol.startswith("tcp"):
                msg = syslog.encode("utf-8")
                data.append(f"{len(msg)} ".encode("utf-8") + msg)
            else:
                data.append(syslog.encode("utf-8"))

        while True:
            attempt += 1
            try:
                assert self._sock is not None
                for payload in data:
                    if self.cfg.protocol == "udp":
                        self._sock.sendto(payload, (self.cfg.host, self.cfg.port))
                    else:
                        self._sock.sendall(payload)
                self._cb.on_success()
                sent = len(batch)
                break
            except Exception as e:
                self._cb.on_failure()
                if attempt >= self.cfg.max_attempts:
                    logger.error("syslog.cef.export.fail", extra={"err": str(e)[:200]})
                    failed = len(batch)
                    return ExportResult(ok=False, sent=sent, failed=failed, error=str(e)[:200])
                await asyncio.sleep(min(backoff, self.cfg.backoff_max_ms) / 1000.0)
                backoff = min(backoff * 2, self.cfg.backoff_max_ms)
        return ExportResult(ok=True, sent=sent, failed=failed)

# =============================================================================
# Exporter manager with batching, retries, dedupe
# =============================================================================

@dataclass
class BatcherConfig:
    flush_max_batch: int = 500
    flush_interval_sec: float = 2.0
    queue_maxsize: int = 10000
    parallel_flushes: int = 2
    drop_on_overflow: bool = False  # if False, put() will backpressure

class ExporterManager:
    def __init__(self, exporters: List[Exporter], batcher_cfg: Optional[BatcherConfig] = None):
        self.exporters = exporters
        self.cfg = batcher_cfg or BatcherConfig()
        self._q: asyncio.Queue[AuditEvent] = asyncio.Queue(maxsize=self.cfg.queue_maxsize)
        self._flush_tasks: List[asyncio.Task] = []
        self._stop = asyncio.Event()
        self._metrics = {
            "enqueued": 0,
            "dropped": 0,
            "sent": 0,
            "failed": 0,
        }
        # simple dedupe cache for idempotency keys
        self._idem: Dict[str, float] = {}
        self._idem_ttl_sec = 600

    async def start(self) -> None:
        for e in self.exporters:
            await e.start()
        for _ in range(self.cfg.parallel_flushes):
            self._flush_tasks.append(asyncio.create_task(self._flusher()))

    async def aclose(self) -> None:
        self._stop.set()
        for t in self._flush_tasks:
            t.cancel()
        for e in self.exporters:
            try:
                await e.aclose()
            except Exception:
                pass

    def _idem_ok(self, ev: AuditEvent) -> bool:
        key = ev.idempotency_key or ev.event_id
        now = time.time()
        # prune
        if self._idem and len(self._idem) % 1000 == 0:
            self._idem = {k: v for k, v in self._idem.items() if now - v < self._idem_ttl_sec}
        if key in self._idem and now - self._idem[key] < self._idem_ttl_sec:
            return False
        self._idem[key] = now
        return True

    async def put(self, event: AuditEvent) -> bool:
        if not self._idem_ok(event):
            self._metrics["dropped"] += 1
            return False
        try:
            if self.cfg.drop_on_overflow and self._q.full():
                self._metrics["dropped"] += 1
                return False
            await self._q.put(event)
            self._metrics["enqueued"] += 1
            return True
        except asyncio.CancelledError:
            return False

    async def _flusher(self) -> None:
        batch: List[AuditEvent] = []
        last_flush = time.time()
        try:
            while not self._stop.is_set():
                timeout = self.cfg.flush_interval_sec - (time.time() - last_flush)
                timeout = max(0.0, timeout)
                try:
                    ev = await asyncio.wait_for(self._q.get(), timeout=timeout)
                    batch.append(ev)
                    if len(batch) >= self.cfg.flush_max_batch:
                        await self._flush(batch)
                        batch = []
                        last_flush = time.time()
                except asyncio.TimeoutError:
                    if batch:
                        await self._flush(batch)
                        batch = []
                        last_flush = time.time()
        except asyncio.CancelledError:
            if batch:
                await self._flush(batch)

    async def _flush(self, batch: List[AuditEvent]) -> None:
        if not batch:
            return
        tasks = [exp.export(batch) for exp in self.exporters]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        sent, failed = 0, 0
        for res in results:
            if isinstance(res, ExportResult):
                sent += res.sent
                failed += res.failed
                if not res.ok:
                    logger.warning("exporter.failed", extra={"error": res.error})
            else:
                failed += len(batch)
                logger.error("exporter.exception", extra={"error": str(res)[:200]})
        self._metrics["sent"] += sent // max(1, len(self.exporters))
        self._metrics["failed"] += failed // max(1, len(self.exporters))

    def metrics(self) -> Dict[str, int]:
        return dict(self._metrics)

# =============================================================================
# Example wiring
# =============================================================================

async def _example():
    # Configure exporters
    splunk = SplunkHECExporter(SplunkHECConfig(
        url=os.getenv("SPLUNK_HEC_URL", "https://splunk.example.com:8088/services/collector"),
        token=os.getenv("SPLUNK_HEC_TOKEN", "REPLACE"),
        index=os.getenv("SPLUNK_INDEX", None),
        host=os.uname().nodename if hasattr(os, "uname") else "host",
        verify_ssl=True,
    ))
    elastic = ElasticBulkExporter(ElasticBulkConfig(
        url=os.getenv("ELASTIC_URL", "https://es.example.com:9200"),
        index_prefix=os.getenv("ELASTIC_INDEX_PREFIX", "security-core-audit"),
        username=os.getenv("ELASTIC_USER"),
        password=os.getenv("ELASTIC_PASS"),
        verify_ssl=True,
    ))
    syslog_cef = SyslogCEFExporter(SyslogCEFConfig(
        host=os.getenv("SYSLOG_HOST", "127.0.0.1"),
        port=int(os.getenv("SYSLOG_PORT", "514")),
        protocol=os.getenv("SYSLOG_PROTO", "udp"),
    ))

    mgr = ExporterManager([splunk, elastic, syslog_cef], BatcherConfig(
        flush_max_batch=200,
        flush_interval_sec=1.0,
        queue_maxsize=5000,
        parallel_flushes=2,
    ))
    await mgr.start()

    # Produce demo events
    for i in range(10):
        ev = AuditEvent(
            action="user.login",
            outcome="SUCCESS",
            severity="INFO",
            actor_id="u-123",
            target_type="session",
            target_id=str(i),
            source="auth-service",
            ip="10.0.0.1",
            tenant_id="t1",
            trace_id=uuid.uuid4().hex,
            attributes={"method": "PASSWORD", "mfa": True},
        )
        await mgr.put(ev)

    await asyncio.sleep(2.5)
    print("metrics:", mgr.metrics())
    await mgr.aclose()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    try:
        asyncio.run(_example())
    except KeyboardInterrupt:
        pass
