# security-core/security/workers/audit_shipper.py
# Industrial audit events shipper with durable local queue, batching, retries, HMAC signing, and optional TLS pinning.
# Python 3.10+
#
# Dependencies: stdlib only. If 'aiohttp' is installed, HTTP sink will use it for async I/O and TLS fingerprint pinning.

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import gzip
import hmac
import hashlib
import json
import os
import random
import signal
import ssl
import string
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Protocol, Union

# =========================
# Data model
# =========================

@dataclass(frozen=True)
class AuditEvent:
    # Required minimal fields; extend as needed, 'meta' for extra attributes.
    event_id: str
    ts_ms: int
    type: str
    actor: Mapping[str, Any]
    target: Mapping[str, Any]
    action: str
    outcome: str  # "success" | "failure" | "unknown"
    source: Mapping[str, Any] = field(default_factory=dict)
    meta: Mapping[str, Any] = field(default_factory=dict)

    def to_canonical_json(self) -> bytes:
        # Deterministic JSON for HMAC reproducibility
        return json.dumps(dataclasses.asdict(self), separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")


def new_event(
    *,
    type: str,
    actor: Mapping[str, Any],
    target: Mapping[str, Any],
    action: str,
    outcome: str,
    source: Mapping[str, Any] | None = None,
    meta: Mapping[str, Any] | None = None,
) -> AuditEvent:
    return AuditEvent(
        event_id=str(uuid.uuid4()),
        ts_ms=int(time.time() * 1000),
        type=type,
        actor=dict(actor),
        target=dict(target),
        action=action,
        outcome=outcome,
        source=dict(source or {}),
        meta=dict(meta or {}),
    )

# =========================
# Config and policies
# =========================

@dataclass
class RetryPolicy:
    initial_backoff_ms: int = 200
    max_backoff_ms: int = 15_000
    multiplier: float = 2.0
    jitter: float = 0.2          # 0.2 => ±20%

@dataclass
class QueuePolicy:
    max_in_memory: int = 10_000   # events
    on_overflow: str = "block"    # "block" | "drop_oldest"

@dataclass
class BatchPolicy:
    max_events: int = 500
    max_bytes: int = 512 * 1024
    linger_ms: int = 250

@dataclass
class HmacConfig:
    enabled: bool = True
    key_id: str = "default"
    key_bytes: bytes = b"change_me"
    hash_alg: str = "sha256"      # "sha256" | "sha384" | "sha512"
    header_name: str = "X-Audit-Signature"

@dataclass
class HttpConfig:
    url: str = "http://localhost:8080/audit"
    timeout_sec: float = 5.0
    verify_tls: bool = True
    ca_path: Optional[str] = None
    tls_fingerprint_sha256: Optional[str] = None  # hex without colons; aiohttp only
    proxy_url: Optional[str] = None
    extra_headers: Mapping[str, str] = field(default_factory=dict)
    method: str = "POST"
    compression: str = "gzip"  # "gzip" | "none"

@dataclass
class FileSinkConfig:
    path: str = "/var/log/security-core/audit-export.ndjson"

@dataclass
class WalConfig:
    dir: str = "/var/lib/security-core/audit-wal"
    fsync: bool = True
    max_pending_segments: int = 50_000
    segment_prefix: str = "seg"
    # per-segment caps; фактический батч формируется независимо, сегмент — упаковка на диск
    segment_max_events: int = 5_000
    segment_max_bytes: int = 5 * 1024 * 1024

@dataclass
class ShipperConfig:
    worker_count: int = 2
    inflight_batches: int = 8
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    queue: QueuePolicy = field(default_factory=QueuePolicy)
    batch: BatchPolicy = field(default_factory=BatchPolicy)
    wal: WalConfig = field(default_factory=WalConfig)
    hmac: HmacConfig = field(default_factory=HmacConfig)
    http: Optional[HttpConfig] = field(default_factory=HttpConfig)
    file: Optional[FileSinkConfig] = None


# =========================
# Sink protocol
# =========================

class Sink(Protocol):
    async def send(self, *, payload: bytes, headers: Mapping[str, str], idempotency_key: str, timeout_sec: float) -> None: ...
    async def close(self) -> None: ...


# =========================
# Utility helpers
# =========================

def _b64url(b: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")

def _sign_hmac(cfg: HmacConfig, body: bytes) -> str:
    if not cfg.enabled:
        return ""
    alg = cfg.hash_alg.lower()
    if alg == "sha256":
        dig = hmac.new(cfg.key_bytes, body, hashlib.sha256).digest()
        a = "HMAC-SHA256"
    elif alg == "sha384":
        dig = hmac.new(cfg.key_bytes, body, hashlib.sha384).digest()
        a = "HMAC-SHA384"
    elif alg == "sha512":
        dig = hmac.new(cfg.key_bytes, body, hashlib.sha512).digest()
        a = "HMAC-SHA512"
    else:
        raise ValueError("unsupported HMAC algorithm")
    return f'alg="{a}",kid="{cfg.key_id}",sig="{_b64url(dig)}"'

def _gzip_if_needed(data: bytes, compression: str) -> Tuple[bytes, Optional[str]]:
    if compression == "gzip":
        return gzip.compress(data, mtime=0), "gzip"
    return data, None

def _now_ms() -> int:
    return int(time.time() * 1000)

def _rand_idem_key() -> str:
    # 20 random URL-safe chars
    alphabet = string.ascii_letters + string.digits + "-_"
    return "".join(random.choice(alphabet) for _ in range(20))

def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

# =========================
# WAL store (segment files)
# =========================

class WalStore:
    """
    Disk-backed queue with two directories: pending/ and inflight/.
    Each segment is an NDJSON file with header metadata (.json) and body (.ndjson).
    Atomicity is achieved via write to pending/ then os.replace to publish.
    On success ship, segment is removed. On failure, inflight/ segment is moved back to pending/.
    """

    def __init__(self, cfg: WalConfig) -> None:
        self.cfg = cfg
        self.root = Path(cfg.dir)
        self.dir_pending = self.root / "pending"
        self.dir_inflight = self.root / "inflight"
        _ensure_dir(self.dir_pending)
        _ensure_dir(self.dir_inflight)
        self._lock = asyncio.Lock()

    def _new_seg_name(self) -> str:
        # Monotonic timestamp + random suffix
        return f"{self.cfg.segment_prefix}-{int(time.time()*1000)}-{uuid.uuid4().hex}"

    async def append_events(self, events: List[AuditEvent]) -> Path:
        """
        Pack a new segment with provided events into pending/.
        """
        if not events:
            raise ValueError("no events to append")
        seg_name = self._new_seg_name()
        tmp = self.dir_pending / f".{seg_name}.tmp"
        final = self.dir_pending / f"{seg_name}.ndjson"

        # Write NDJSON
        with tmp.open("wb") as f:
            for ev in events:
                line = ev.to_canonical_json() + b"\n"
                f.write(line)
            if self.cfg.fsync:
                f.flush()
                os.fsync(f.fileno())
        os.replace(tmp, final)
        return final

    async def list_pending(self) -> List[Path]:
        return sorted(p for p in self.dir_pending.glob("*.ndjson"))

    async def list_inflight(self) -> List[Path]:
        return sorted(p for p in self.dir_inflight.glob("*.ndjson"))

    async def checkout(self, seg: Path) -> Path:
        """
        Move segment to inflight/ atomically, return new path.
        """
        newp = self.dir_inflight / seg.name
        os.replace(seg, newp)
        return newp

    async def commit(self, inflight_seg: Path) -> None:
        with contextlib.suppress(FileNotFoundError):
            inflight_seg.unlink()

    async def rollback(self, inflight_seg: Path) -> Path:
        # Move back to pending
        back = self.dir_pending / inflight_seg.name
        with contextlib.suppress(FileNotFoundError):
            os.replace(inflight_seg, back)
        return back

    async def read_segment(self, seg: Path, max_events: int | None = None, max_bytes: int | None = None) -> Tuple[List[bytes], int]:
        """
        Read up to limits from segment. Returns (lines, total_bytes).
        """
        lines: List[bytes] = []
        total = 0
        nlimit = max_events or 1_000_000_000
        blimit = max_bytes or 1 << 62
        with seg.open("rb") as f:
            for line in f:
                if not line:
                    break
                if len(lines) >= nlimit or (total + len(line)) > blimit:
                    break
                lines.append(line.rstrip(b"\n"))
                total += len(line)
        return lines, total

# =========================
# Sinks
# =========================

class FileSink(Sink):
    def __init__(self, cfg: FileSinkConfig) -> None:
        self._path = Path(cfg.path)
        _ensure_dir(self._path.parent)
        self._lock = asyncio.Lock()

    async def send(self, *, payload: bytes, headers: Mapping[str, str], idempotency_key: str, timeout_sec: float) -> None:
        # Append one line: {"idempotency_key":..., "headers":..., "payload_b64":...}
        import base64
        rec = {
            "ts_ms": _now_ms(),
            "idempotency_key": idempotency_key,
            "headers": dict(headers),
            "payload_b64": base64.b64encode(payload).decode("ascii"),
        }
        line = json.dumps(rec, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
        async with self._lock:
            loop = asyncio.get_running_loop()
            def _write():
                with self._path.open("ab") as f:
                    f.write(line)
                    f.flush()
                    os.fsync(f.fileno())
            await loop.run_in_executor(None, _write)

    async def close(self) -> None:
        return

class HttpSink(Sink):
    """
    HTTP sink with optional aiohttp; otherwise uses stdlib in thread pool.
    Supports gzip body; HMAC header is prepared by caller.
    """
    def __init__(self, cfg: HttpConfig) -> None:
        self.cfg = cfg
        self._aiohttp = None
        self._session = None
        try:
            import aiohttp  # type: ignore
            self._aiohttp = aiohttp
        except Exception:
            self._aiohttp = None

    async def _ensure_session(self):
        if not self._aiohttp or self._session:
            return
        aiohttp = self._aiohttp
        assert aiohttp is not None
        # SSL context
        ssl_ctx = None
        if self.cfg.verify_tls:
            ssl_ctx = ssl.create_default_context(cafile=self.cfg.ca_path) if self.cfg.ca_path else ssl.create_default_context()
        else:
            ssl_ctx = ssl._create_unverified_context()
        # Fingerprint, if set (aiohttp supports it)
        fp = None
        if self.cfg.tls_fingerprint_sha256:
            raw = bytes.fromhex(self.cfg.tls_fingerprint_sha256.lower())
            fp = raw
        self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.cfg.timeout_sec), trust_env=True)

        # Store ssl and fingerprint for per-request connector use
        self._ssl_ctx = ssl_ctx
        self._fp = fp

    async def send(self, *, payload: bytes, headers: Mapping[str, str], idempotency_key: str, timeout_sec: float) -> None:
        hdrs = {"Content-Type": "application/json", "X-Idempotency-Key": idempotency_key}
        hdrs.update(self.cfg.extra_headers)
        hdrs.update(headers)

        if self._aiohttp:
            await self._ensure_session()
            aiohttp = self._aiohttp
            assert self._session is not None
            # For TLS pinning in aiohttp: use fingerprint parameter on connector per request
            ssl_ctx = getattr(self, "_ssl_ctx", None)
            fp = getattr(self, "_fp", None)
            # Note: aiohttp supports 'fingerprint' only on TCPConnector construction; emulate via temporary session if fp is set
            if fp is not None:
                conn = aiohttp.TCPConnector(ssl=ssl_ctx, fingerprint=fp)
                async with aiohttp.ClientSession(connector=conn, timeout=aiohttp.ClientTimeout(total=timeout_sec), trust_env=True) as s:
                    async with s.request(self.cfg.method, self.cfg.url, data=payload, headers=hdrs, proxy=self.cfg.proxy_url) as resp:
                        if resp.status >= 300:
                            body = await resp.text()
                            raise RuntimeError(f"HTTP sink error {resp.status}: {body[:200]}")
            else:
                async with self._session.request(self.cfg.method, self.cfg.url, data=payload, headers=hdrs, proxy=self.cfg.proxy_url, ssl=ssl_ctx) as resp:
                    if resp.status >= 300:
                        body = await resp.text()
                        raise RuntimeError(f"HTTP sink error {resp.status}: {body[:200]}")
            return

        # Fallback: stdlib in thread pool
        import urllib.request
        req = urllib.request.Request(self.cfg.url, data=payload, method=self.cfg.method)
        for k, v in hdrs.items():
            req.add_header(k, v)
        # SSL context
        context = None
        if self.cfg.url.lower().startswith("https"):
            if self.cfg.verify_tls:
                context = ssl.create_default_context(cafile=self.cfg.ca_path) if self.cfg.ca_path else ssl.create_default_context()
            else:
                context = ssl._create_unverified_context()
        loop = asyncio.get_running_loop()

        def _do_request():
            with contextlib.closing(urllib.request.urlopen(req, timeout=timeout_sec, context=context)) as r:
                st = getattr(r, "status", 200)
                if st and st >= 300:
                    raise RuntimeError(f"HTTP sink error {st}")

        await loop.run_in_executor(None, _do_request)

    async def close(self) -> None:
        if self._session:
            await self._session.close()
            self._session = None

# =========================
# AuditShipper
# =========================

class AuditShipper:
    """
    Core orchestrator: accepts events, persists to WAL, forms batches, and sends via sink with retries.
    """

    def __init__(self, cfg: ShipperConfig) -> None:
        self.cfg = cfg
        self._queue: asyncio.Queue[AuditEvent] = asyncio.Queue(maxsize=cfg.queue.max_in_memory)
        self._wal = WalStore(cfg.wal)
        # Choose sink
        if cfg.file:
            self._sink: Sink = FileSink(cfg.file)
        elif cfg.http:
            self._sink = HttpSink(cfg.http)
        else:
            raise ValueError("no sink configured")
        self._stop = asyncio.Event()
        self._started = False
        self._workers: List[asyncio.Task] = []
        self._batcher_task: Optional[asyncio.Task] = None
        self._sem_inflight = asyncio.Semaphore(cfg.inflight_batches)
        # Stats
        self._stats = {
            "accepted": 0,
            "dropped": 0,
            "batched": 0,
            "sent_batches": 0,
            "retries": 0,
            "failed_batches": 0,
            "wal_pending": 0,
        }

    # -------- Public API --------

    async def start(self) -> None:
        if self._started:
            return
        self._started = True
        # Recover pending segments into work
        # Nothing to do now; workers will pick from WAL directly.
        self._batcher_task = asyncio.create_task(self._batcher_loop(), name="audit-batcher")
        for i in range(self.cfg.worker_count):
            self._workers.append(asyncio.create_task(self._worker_loop(i), name=f"audit-worker-{i}"))

    async def stop(self, *, flush: bool = True, timeout: float = 10.0) -> None:
        if not self._started:
            return
        if flush:
            # Wait for queue to drain
            try:
                await asyncio.wait_for(self._queue.join(), timeout=timeout)
            except asyncio.TimeoutError:
                pass
        self._stop.set()
        if self._batcher_task:
            await self._batcher_task
        await asyncio.gather(*self._workers, return_exceptions=True)
        await self._sink.close()
        self._started = False

    def health(self) -> Dict[str, Any]:
        return dict(self._stats)

    async def emit(self, ev: AuditEvent) -> None:
        """
        Add event to in-memory queue with overflow policy.
        """
        policy = self.cfg.queue
        if policy.on_overflow == "block":
            await self._queue.put(ev)
            self._stats["accepted"] += 1
            return

        # drop_oldest
        if self._queue.full():
            try:
                _ = self._queue.get_nowait()
                self._queue.task_done()
                self._stats["dropped"] += 1
            except asyncio.QueueEmpty:
                pass
        try:
            self._queue.put_nowait(ev)
            self._stats["accepted"] += 1
        except asyncio.QueueFull:
            self._stats["dropped"] += 1

    # -------- Internal loops --------

    async def _batcher_loop(self) -> None:
        """
        Aggregate events from queue into WAL segments respecting size/linger limits.
        """
        batch_events: List[AuditEvent] = []
        batch_bytes = 0
        next_deadline = None

        async def _flush():
            nonlocal batch_events, batch_bytes, next_deadline
            if not batch_events:
                return
            # Persist to WAL segment
            await self._wal.append_events(batch_events)
            self._stats["batched"] += len(batch_events)
            batch_events = []
            batch_bytes = 0
            next_deadline = None

        try:
            while not self._stop.is_set():
                # Determine linger deadline
                if next_deadline is None and batch_events:
                    next_deadline = _now_ms() + self.cfg.batch.linger_ms

                timeout = None
                if next_deadline is not None:
                    remain = max(0, next_deadline - _now_ms()) / 1000.0
                    timeout = remain

                try:
                    ev = await asyncio.wait_for(self._queue.get(), timeout=timeout)
                    size = len(ev.to_canonical_json()) + 1
                    if (len(batch_events) + 1 > self.cfg.batch.max_events) or (batch_bytes + size > self.cfg.batch.max_bytes):
                        await _flush()
                    batch_events.append(ev)
                    batch_bytes += size
                    self._queue.task_done()
                except asyncio.TimeoutError:
                    await _flush()
        finally:
            # Final flush
            await _flush()

    async def _worker_loop(self, worker_id: int) -> None:
        """
        Pull segments from WAL and send them with retries.
        """
        while not self._stop.is_set():
            # Prefer inflight (retries), then pending
            infl = await self._wal.list_inflight()
            pend = await self._wal.list_pending()
            self._stats["wal_pending"] = len(infl) + len(pend)
            seg = None
            if infl:
                seg = infl[0]
            elif pend:
                seg = await self._wal.checkout(pend[0])
            else:
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=0.250)
                except asyncio.TimeoutError:
                    continue
                else:
                    break

            if seg is None:
                continue

            # Read limited portion for batch sending
            lines, _ = await self._wal.read_segment(seg, max_events=self.cfg.batch.max_events, max_bytes=self.cfg.batch.max_bytes)
            if not lines:
                # Empty segment, delete
                await self._wal.commit(seg)
                continue

            payload = b"[" + b",".join(lines) + b"]"
            payload, enc = _gzip_if_needed(payload, self.cfg.http.compression if self.cfg.http else "none")
            headers = {}
            if enc:
                headers["Content-Encoding"] = enc
            # HMAC signature
            if self.cfg.hmac.enabled:
                headers[self.cfg.hmac.header_name] = _sign_hmac(self.cfg.hmac, payload)
            # Idempotency
            idem = _rand_idem_key()

            # Concurrency gate
            async with self._sem_inflight:
                ok = await self._send_with_retries(payload, headers, idem)

            if ok:
                await self._wal.commit(seg)
                self._stats["sent_batches"] += 1
            else:
                # Move back to pending for next attempt
                await self._wal.rollback(seg)
                self._stats["failed_batches"] += 1
                # Brief pause to avoid hot loop
                await asyncio.sleep(0.5)

    async def _send_with_retries(self, payload: bytes, headers: Mapping[str, str], idem: str) -> bool:
        backoff = self.cfg.retry.initial_backoff_ms
        attempt = 0
        while not self._stop.is_set():
            try:
                await self._sink.send(
                    payload=payload,
                    headers=headers,
                    idempotency_key=idem,
                    timeout_sec=self.cfg.http.timeout_sec if self.cfg.http else 5.0,
                )
                return True
            except Exception as e:
                attempt += 1
                self._stats["retries"] += 1
                # Compute backoff with jitter
                jitter = 1.0 + random.uniform(-self.cfg.retry.jitter, self.cfg.retry.jitter)
                await asyncio.sleep(min(self.cfg.retry.max_backoff_ms, backoff) / 1000.0 * jitter)
                backoff = min(self.cfg.retry.max_backoff_ms, int(backoff * self.cfg.retry.multiplier))
        return False


# =========================
# Convenience bootstrap
# =========================

def build_default_shipper(root_dir: str = "/var/lib/security-core/audit-wal", url: str = "http://localhost:8080/audit", hmac_key: bytes | None = None) -> AuditShipper:
    cfg = ShipperConfig()
    cfg.wal.dir = root_dir
    cfg.http.url = url
    if hmac_key:
        cfg.hmac.key_bytes = hmac_key
    return AuditShipper(cfg)


# =========================
# Minimal CLI
# =========================

async def _demo() -> None:
    shipper = build_default_shipper()
    await shipper.start()
    # Emit 3 test events
    for i in range(3):
        ev = new_event(
            type="auth",
            actor={"id": "user-123", "ip": "10.0.0.1"},
            target={"type": "session", "id": f"sess-{i}"},
            action="login",
            outcome="success",
            meta={"i": i},
        )
        await shipper.emit(ev)
    # Graceful stop with flush
    await shipper.stop(flush=True)

if __name__ == "__main__":
    # Optional: handle SIGTERM for graceful shutdown
    async def main():
        task = asyncio.create_task(_demo())
        loop = asyncio.get_running_loop()
        stop = asyncio.Event()
        def _sig(*_):
            stop.set()
        for s in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(Exception):
                loop.add_signal_handler(s, _sig)
        await asyncio.wait({task, asyncio.create_task(stop.wait())}, return_when=asyncio.FIRST_COMPLETED)
    asyncio.run(main())
