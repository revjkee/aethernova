# ledger/security/auditor.py
# Industrial-grade security auditor for ledger-core
# Standard library only.

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import sqlite3
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple, Union

# -----------------------------
# Utilities
# -----------------------------

UTC = dt.timezone.utc

def _utcnow() -> dt.datetime:
    return dt.datetime.now(tz=UTC)

def _iso(ts: dt.datetime) -> str:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts.astimezone(UTC).isoformat(timespec="milliseconds")

def _hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown-host"

def _json_dumps(obj: Any) -> str:
    # Stable canonical JSON for hashing
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def _sha256(data: Union[str, bytes]) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def _safe_uuid() -> str:
    return uuid.uuid4().hex

def _validate_ip(ip: Optional[str]) -> Optional[str]:
    if not ip:
        return None
    try:
        return str(ipaddress.ip_address(ip))
    except Exception:
        return None

def _truncate(s: str, max_len: int) -> str:
    return s if len(s) <= max_len else s[: max_len - 3] + "..."

# -----------------------------
# Event Model
# -----------------------------

class Severity(str, Enum):
    INFO = "INFO"
    NOTICE = "NOTICE"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    SECURITY = "SECURITY"

class EventType(str, Enum):
    ACCESS = "ACCESS"
    ACTION = "ACTION"
    CONFIG = "CONFIG"
    TRANSACTION = "TRANSACTION"
    SECURITY = "SECURITY"
    SYSTEM = "SYSTEM"
    AUDIT = "AUDIT"

@dataclass
class AuditEvent:
    # Identity
    event_id: str
    ts: str
    type: EventType
    severity: Severity

    # Actors and targets
    actor: str
    action: str
    resource: str

    # Context
    ip: Optional[str] = None
    location: Optional[str] = None
    user_agent: Optional[str] = None
    status: Optional[str] = None  # e.g. SUCCESS|DENIED|FAILED
    code: Optional[str] = None    # e.g. error/deny code
    meta: Dict[str, Any] = field(default_factory=dict)

    # Ledger/app tags
    app: Optional[str] = None
    env: Optional[str] = None
    host: Optional[str] = None

    # Integrity chain
    prev_hash: Optional[str] = None   # previous event chain hash
    chain_hash: Optional[str] = None  # current event hash (computed)
    mac: Optional[str] = None         # optional HMAC over chain_hash

    # Versioning
    schema_version: int = 1

    def to_canonical(self) -> Dict[str, Any]:
        # Exclude fields computed for integrity to derive the canonical payload
        d = asdict(self)
        for k in ("chain_hash", "mac"):
            d.pop(k, None)
        return d

# -----------------------------
# Redaction / PII masking
# -----------------------------

@dataclass
class RedactionRule:
    name: str
    pattern: re.Pattern
    replacement: str = "<REDACTED>"

DEFAULT_REDACTION_RULES: List[RedactionRule] = [
    RedactionRule("email", re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b")),
    RedactionRule("phone", re.compile(r"\b(?:\+?\d{1,3}[-. ]?)?(?:\(?\d{3}\)?[-. ]?)?\d{3}[-. ]?\d{2,4}\b")),
    RedactionRule("card", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
    RedactionRule("ssn_like", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    RedactionRule("secret", re.compile(r"(?i)(api[_-]?key|secret|token)[=:]\s*[0-9a-zA-Z\-_]{8,}")),
]

def redact_value(val: Any, rules: List[RedactionRule]) -> Any:
    if val is None:
        return None
    if isinstance(val, str):
        s = val
        for r in rules:
            s = r.pattern.sub(r.replacement, s)
        return s
    if isinstance(val, dict):
        return {k: redact_value(v, rules) for k, v in val.items()}
    if isinstance(val, list):
        return [redact_value(x, rules) for x in val]
    return val

# -----------------------------
# Auditor Config
# -----------------------------

@dataclass
class AuditorConfig:
    app: str = "ledger-core"
    env: str = "prod"
    host: str = field(default_factory=_hostname)

    # Integrity
    hmac_secret: Optional[bytes] = None        # if set, mac = HMAC(secret, chain_hash)
    chain_seed: str = "ledger-audit-seed"      # initial prev_hash if none
    include_prev_mac: bool = False             # chain mac over previous mac as well (stronger)

    # Queue/Batch
    batch_size: int = 100
    flush_interval_s: float = 1.0
    max_queue: int = 10000

    # Redaction
    redaction_rules: List[RedactionRule] = field(default_factory=lambda: list(DEFAULT_REDACTION_RULES))
    truncate_meta_at: int = 10_000  # guardrail for huge blobs

    # File sink settings
    file_dir: Path = Path("./audit-logs")
    file_prefix: str = "audit"
    rotate_max_bytes: int = 128 * 1024 * 1024  # 128MB
    rotate_daily: bool = True
    retention_days: int = 90

    # SQLite sink settings
    sqlite_path: Path = Path("./audit-logs/audit.sqlite")

# -----------------------------
# Sink Protocol
# -----------------------------

class AuditSink(Protocol):
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def get_last_chain_hash(self) -> Optional[str]: ...
    def write_batch(self, events: List[AuditEvent]) -> None: ...
    def verify(self, hmac_secret: Optional[bytes]) -> Tuple[bool, List[str]]: ...

# -----------------------------
# File JSONL Sink with rotation/retention
# -----------------------------

class FileAuditSink:
    def __init__(self, cfg: AuditorConfig) -> None:
        self.cfg = cfg
        self._lock = threading.RLock()
        self._file: Optional[Path] = None
        self._fh = None  # type: ignore
        self._last_hash: Optional[str] = None

    def start(self) -> None:
        self.cfg.file_dir.mkdir(parents=True, exist_ok=True)
        self._open_file()

    def stop(self) -> None:
        with self._lock:
            if self._fh:
                try:
                    self._fh.flush()
                    os.fsync(self._fh.fileno())
                except Exception:
                    pass
                try:
                    self._fh.close()
                finally:
                    self._fh = None

    def _current_filename(self) -> Path:
        date_tag = _utcnow().strftime("%Y-%m-%d") if self.cfg.rotate_daily else "static"
        return self.cfg.file_dir / f"{self.cfg.file_prefix}-{date_tag}.jsonl"

    def _open_file(self) -> None:
        with self._lock:
            self._file = self._current_filename()
            self._fh = open(self._file, "a+", encoding="utf-8")
            self._fh.seek(0)
            # try to read last line to recover last hash
            try:
                last_line = self._tail_last_line(self._fh)
                if last_line:
                    ev = json.loads(last_line)
                    self._last_hash = ev.get("chain_hash") or None
            except Exception:
                self._last_hash = None

    @staticmethod
    def _tail_last_line(fh) -> Optional[str]:
        try:
            fh.seek(0, os.SEEK_END)
            pos = fh.tell()
            if pos == 0:
                return None
            step = 4096
            buf = ""
            while pos > 0:
                pos = max(0, pos - step)
                fh.seek(pos)
                chunk = fh.read(step)
                buf = chunk + buf
                if "\n" in buf:
                    lines = buf.strip().splitlines()
                    return lines[-1] if lines else None
            lines = buf.strip().splitlines()
            return lines[-1] if lines else None
        except Exception:
            return None

    def _should_rotate(self) -> bool:
        if not self._file:
            return True
        if self.cfg.rotate_daily:
            current = self._current_filename()
            if current != self._file:
                return True
        try:
            return self._file.stat().st_size >= self.cfg.rotate_max_bytes
        except Exception:
            return False

    def _rotate(self) -> None:
        with self._lock:
            self.stop()
            self._open_file()
            self._apply_retention()

    def _apply_retention(self) -> None:
        # Remove files older than retention_days
        days = self.cfg.retention_days
        if days <= 0:
            return
        cutoff = time.time() - days * 86400
        for p in self.cfg.file_dir.glob(f"{self.cfg.file_prefix}-*.jsonl"):
            try:
                if p.stat().st_mtime < cutoff:
                    p.unlink(missing_ok=True)
            except Exception:
                pass

    def write_batch(self, events: List[AuditEvent]) -> None:
        if not events:
            return
        with self._lock:
            if self._should_rotate():
                self._rotate()
            assert self._fh is not None
            for ev in events:
                line = _json_dumps(asdict(ev))
                self._fh.write(line + "\n")
            try:
                self._fh.flush()
                os.fsync(self._fh.fileno())
            except Exception:
                pass
            # update last hash
            self._last_hash = events[-1].chain_hash

    def get_last_chain_hash(self) -> Optional[str]:
        with self._lock:
            return self._last_hash

    def start_verifier_iter(self) -> Iterable[Dict[str, Any]]:
        # Iterate all files in chronological order
        files = sorted(self.cfg.file_dir.glob(f"{self.cfg.file_prefix}-*.jsonl"))
        for fp in files:
            with open(fp, "r", encoding="utf-8") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    try:
                        yield json.loads(line)
                    except Exception:
                        yield {"_corrupt_line": _truncate(line, 256)}

    def verify(self, hmac_secret: Optional[bytes]) -> Tuple[bool, List[str]]:
        ok = True
        issues: List[str] = []
        last_hash: Optional[str] = None

        for rec in self.start_verifier_iter():
            if "_corrupt_line" in rec:
                ok = False
                issues.append("Corrupt JSONL line encountered")
                continue
            rec_prev = rec.get("prev_hash")
            if last_hash and rec_prev != last_hash:
                ok = False
                issues.append(f"Broken chain: prev_hash mismatch for event {rec.get('event_id')}")
            # recompute chain hash
            canonical = dict(rec)
            canonical.pop("chain_hash", None)
            mac = canonical.pop("mac", None)
            ch = _sha256(_json_dumps(canonical))
            if ch != rec.get("chain_hash"):
                ok = False
                issues.append(f"Chain hash mismatch for event {rec.get('event_id')}")
            if hmac_secret:
                calc_mac = hmac.new(hmac_secret, ch.encode("utf-8"), hashlib.sha256).hexdigest()
                if mac != calc_mac:
                    ok = False
                    issues.append(f"HMAC mismatch for event {rec.get('event_id')}")
            last_hash = rec.get("chain_hash")
        return ok, issues

# -----------------------------
# SQLite Sink
# -----------------------------

class SQLiteAuditSink:
    def __init__(self, cfg: AuditorConfig) -> None:
        self.cfg = cfg
        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None
        self._last_hash: Optional[str] = None

    def start(self) -> None:
        self.cfg.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.cfg.sqlite_path.as_posix(), check_same_thread=False)
        self._conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_events (
            ts TEXT NOT NULL,
            event_id TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            severity TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            ip TEXT,
            location TEXT,
            user_agent TEXT,
            status TEXT,
            code TEXT,
            meta TEXT,
            app TEXT,
            env TEXT,
            host TEXT,
            prev_hash TEXT,
            chain_hash TEXT,
            mac TEXT,
            schema_version INTEGER NOT NULL
        );
        """)
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts);")
        self._conn.commit()
        # recover last hash
        cur = self._conn.execute("SELECT chain_hash FROM audit_events ORDER BY ts DESC LIMIT 1;")
        row = cur.fetchone()
        self._last_hash = row[0] if row and row[0] else None

    def stop(self) -> None:
        with self._lock:
            if self._conn:
                try:
                    self._conn.commit()
                except Exception:
                    pass
                self._conn.close()
                self._conn = None

    def write_batch(self, events: List[AuditEvent]) -> None:
        if not events:
            return
        rows = []
        for ev in events:
            rows.append((
                ev.ts, ev.event_id, ev.type.value, ev.severity.value, ev.actor, ev.action, ev.resource,
                ev.ip, ev.location, ev.user_agent, ev.status, ev.code,
                _json_dumps(ev.meta),
                ev.app, ev.env, ev.host, ev.prev_hash, ev.chain_hash, ev.mac, ev.schema_version
            ))
        with self._lock:
            assert self._conn is not None
            self._conn.executemany("""
            INSERT INTO audit_events (
                ts, event_id, type, severity, actor, action, resource,
                ip, location, user_agent, status, code, meta, app, env, host,
                prev_hash, chain_hash, mac, schema_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, rows)
            self._conn.commit()
            self._last_hash = events[-1].chain_hash

    def get_last_chain_hash(self) -> Optional[str]:
        with self._lock:
            return self._last_hash

    def verify(self, hmac_secret: Optional[bytes]) -> Tuple[bool, List[str]]:
        assert self._conn is not None
        ok = True
        issues: List[str] = []
        last_hash: Optional[str] = None
        cur = self._conn.execute("""
            SELECT ts,event_id,type,severity,actor,action,resource,ip,location,user_agent,status,code,meta,app,env,host,prev_hash,chain_hash,mac,schema_version
            FROM audit_events ORDER BY ts ASC, event_id ASC
        """)
        for row in cur:
            rec = {
                "ts": row[0], "event_id": row[1], "type": row[2], "severity": row[3],
                "actor": row[4], "action": row[5], "resource": row[6], "ip": row[7], "location": row[8],
                "user_agent": row[9], "status": row[10], "code": row[11], "meta": json.loads(row[12] or "{}"),
                "app": row[13], "env": row[14], "host": row[15], "prev_hash": row[16],
                "chain_hash": row[17], "mac": row[18], "schema_version": row[19]
            }
            if last_hash and rec["prev_hash"] != last_hash:
                ok = False
                issues.append(f"Broken chain at {rec['event_id']}")
            canonical = dict(rec)
            canonical.pop("chain_hash", None)
            mac_val = canonical.pop("mac", None)
            ch = _sha256(_json_dumps(canonical))
            if ch != rec["chain_hash"]:
                ok = False
                issues.append(f"Chain hash mismatch at {rec['event_id']}")
            if hmac_secret:
                calc_mac = hmac.new(hmac_secret, ch.encode("utf-8"), hashlib.sha256).hexdigest()
                if mac_val != calc_mac:
                    ok = False
                    issues.append(f"HMAC mismatch at {rec['event_id']}")
            last_hash = rec["chain_hash"]
        return ok, issues

# -----------------------------
# Auditor core
# -----------------------------

class Auditor:
    """
    Asynchronous, batch-enabled auditor with tamper-evident hash chain and optional HMAC.
    """

    def __init__(self, *,
                 cfg: Optional[AuditorConfig] = None,
                 sink: Optional[AuditSink] = None) -> None:
        self.cfg = cfg or AuditorConfig()
        self.sink = sink or FileAuditSink(self.cfg)
        self._queue: asyncio.Queue[AuditEvent] = asyncio.Queue(maxsize=self.cfg.max_queue)
        self._bg_task: Optional[asyncio.Task] = None
        self._stopped = asyncio.Event()
        self._last_chain_hash: Optional[str] = None
        self._last_mac: Optional[str] = None
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        # Start sink in a thread as it's blocking
        await loop.run_in_executor(None, self.sink.start)
        self._last_chain_hash = self.sink.get_last_chain_hash()
        self._bg_task = asyncio.create_task(self._flusher_loop())

    async def stop(self) -> None:
        self._stopped.set()
        if self._bg_task:
            await self._bg_task
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self.sink.stop)

    async def _flusher_loop(self) -> None:
        batch: List[AuditEvent] = []
        last_flush = time.monotonic()
        while not self._stopped.is_set():
            try:
                timeout = self.cfg.flush_interval_s
                item = await asyncio.wait_for(self._queue.get(), timeout=timeout)
                batch.append(item)
                if len(batch) >= self.cfg.batch_size:
                    self._flush_now(batch)
                    batch.clear()
                    last_flush = time.monotonic()
            except asyncio.TimeoutError:
                if batch:
                    self._flush_now(batch)
                    batch.clear()
                    last_flush = time.monotonic()
                else:
                    # no-op tick: check rotation via sink on write path only
                    pass
            except asyncio.CancelledError:
                break
            except Exception:
                # In production, route to fallback logging
                pass

        if batch:
            self._flush_now(batch)

    def _flush_now(self, batch: List[AuditEvent]) -> None:
        # Blocking write in thread
        def _write():
            self.sink.write_batch(batch)
        # Ensure writes are not concurrent
        _write()

    # ------------- Public API -------------

    async def log(self,
                  *,
                  type: EventType,
                  severity: Severity,
                  actor: str,
                  action: str,
                  resource: str,
                  status: Optional[str] = None,
                  code: Optional[str] = None,
                  ip: Optional[str] = None,
                  location: Optional[str] = None,
                  user_agent: Optional[str] = None,
                  meta: Optional[Dict[str, Any]] = None) -> AuditEvent:
        ev = self._build_event(
            type=type, severity=severity, actor=actor, action=action, resource=resource,
            status=status, code=code, ip=ip, location=location, user_agent=user_agent, meta=meta or {}
        )
        await self._queue.put(ev)
        return ev

    async def log_access(self, **kwargs: Any) -> AuditEvent:
        kwargs.setdefault("type", EventType.ACCESS)
        kwargs.setdefault("severity", Severity.INFO)
        return await self.log(**kwargs)

    async def log_action(self, **kwargs: Any) -> AuditEvent:
        kwargs.setdefault("type", EventType.ACTION)
        kwargs.setdefault("severity", Severity.NOTICE)
        return await self.log(**kwargs)

    async def log_security(self, **kwargs: Any) -> AuditEvent:
        kwargs.setdefault("type", EventType.SECURITY)
        kwargs.setdefault("severity", Severity.SECURITY)
        return await self.log(**kwargs)

    async def audit_verify(self) -> Tuple[bool, List[str]]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.sink.verify, self.cfg.hmac_secret)

    # ------------- Internal helpers -------------

    def _build_event(self, **kwargs: Any) -> AuditEvent:
        # Prepare and sanitize
        meta = kwargs.get("meta") or {}
        # Truncate oversized meta blobs
        meta_json = _json_dumps(meta)
        if len(meta_json) > self.cfg.truncate_meta_at:
            meta = {"_truncated": True, "preview": meta_json[: self.cfg.truncate_meta_at]}

        # Redact PII recursively
        meta = redact_value(meta, self.cfg.redaction_rules)
        actor = redact_value(kwargs.get("actor", "unknown"), self.cfg.redaction_rules)
        action = redact_value(kwargs.get("action", "unknown"), self.cfg.redaction_rules)
        resource = redact_value(kwargs.get("resource", "unknown"), self.cfg.redaction_rules)
        status = redact_value(kwargs.get("status"), self.cfg.redaction_rules)
        code = redact_value(kwargs.get("code"), self.cfg.redaction_rules)
        location = redact_value(kwargs.get("location"), self.cfg.redaction_rules)
        user_agent = redact_value(kwargs.get("user_agent"), self.cfg.redaction_rules)
        ip = _validate_ip(kwargs.get("ip"))

        ev = AuditEvent(
            event_id=_safe_uuid(),
            ts=_iso(_utcnow()),
            type=kwargs.get("type"),
            severity=kwargs.get("severity"),
            actor=str(actor),
            action=str(action),
            resource=str(resource),
            ip=ip,
            location=str(location) if location else None,
            user_agent=str(user_agent) if user_agent else None,
            status=str(status) if status else None,
            code=str(code) if code else None,
            meta=meta,
            app=self.cfg.app,
            env=self.cfg.env,
            host=self.cfg.host,
            prev_hash=self._prev_hash_for_next(),
            schema_version=1,
        )
        # Compute chain hash and MAC
        canonical = ev.to_canonical()
        ev.chain_hash = _sha256(_json_dumps(canonical))
        if self.cfg.hmac_secret:
            ev.mac = hmac.new(self.cfg.hmac_secret, ev.chain_hash.encode("utf-8"), hashlib.sha256).hexdigest()
        # Update state
        self._register_written(ev)
        return ev

    def _prev_hash_for_next(self) -> str:
        # When starting, seed chain with configured anchor
        return self._last_mac if (self.cfg.include_prev_mac and self._last_mac) else (self._last_chain_hash or _sha256(self.cfg.chain_seed))

    def _register_written(self, ev: AuditEvent) -> None:
        # These updates happen before enqueue; ensures deterministic prev for following events
        self._last_chain_hash = ev.chain_hash
        if self.cfg.hmac_secret and ev.mac:
            self._last_mac = ev.mac

# -----------------------------
# Convenience builders
# -----------------------------

def make_file_auditor(cfg: Optional[AuditorConfig] = None) -> Auditor:
    cfg = cfg or AuditorConfig()
    return Auditor(cfg=cfg, sink=FileAuditSink(cfg))

def make_sqlite_auditor(cfg: Optional[AuditorConfig] = None) -> Auditor:
    cfg = cfg or AuditorConfig()
    return Auditor(cfg=cfg, sink=SQLiteAuditSink(cfg))

# -----------------------------
# CLI self-test (optional)
# -----------------------------

async def _selftest() -> int:
    secret = os.urandom(32)
    cfg = AuditorConfig(
        app="ledger-core",
        env="dev",
        hmac_secret=secret,
        include_prev_mac=True,
        rotate_daily=False,
        rotate_max_bytes=10_000_000,
        retention_days=7,
        file_dir=Path("./_audit_test"),
        sqlite_path=Path("./_audit_test/audit.sqlite"),
    )

    # Test both sinks
    for sink_maker in (make_file_auditor, make_sqlite_auditor):
        auditor = sink_maker(cfg)
        await auditor.start()
        try:
            await auditor.log_access(actor="user:alice@example.com", action="login", resource="auth", status="SUCCESS", ip="127.0.0.1", meta={"mfa": True})
            await auditor.log_action(actor="user:alice@example.com", action="create.wallet", resource="wallet:123", status="SUCCESS", meta={"amount": "100.00", "currency": "USD"})
            await auditor.log_security(actor="system", action="policy.update", resource="acl", severity=Severity.SECURITY, status="APPLIED", meta={"rules": 3})
            ok, issues = await auditor.audit_verify()
            print(f"[{sink_maker.__name__}] verify={ok} issues={issues}")
        finally:
            await auditor.stop()
    return 0

if __name__ == "__main__":
    # Simple CLI for smoke test: python -m ledger.security.auditor
    try:
        rc = asyncio.run(_selftest())
    except KeyboardInterrupt:
        rc = 130
    sys.exit(rc)
