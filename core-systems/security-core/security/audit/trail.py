# security-core/security/audit/trail.py
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256, sha384, sha512
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Iterable

from pydantic import BaseModel, Field, ConfigDict

# Optional deps (do not hard fail)
try:
    import httpx  # type: ignore
except Exception:
    httpx = None  # type: ignore

try:
    from aiokafka import AIOKafkaProducer  # type: ignore
except Exception:
    AIOKafkaProducer = None  # type: ignore

# Optional integration with our crypto signer (asymmetric signatures)
try:
    from security_core.security.crypto.signer import (
        Signer as AsymSigner,
        SignOptions,
        SignatureAlgorithm,
        HashAlgorithm,
    )
except Exception:
    AsymSigner = None  # type: ignore

# -------------------------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------------------------

logger = logging.getLogger("security_core.audit.trail")
if not logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logger.addHandler(h)
logger.setLevel(logging.INFO)

# -------------------------------------------------------------------------------------
# Models
# -------------------------------------------------------------------------------------

class Actor(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: str = Field(description="HUMAN|SERVICE|SYSTEM")
    actor_id: str = Field(description="Unique identifier of the principal")
    roles: List[str] = Field(default_factory=list)
    tenant: Optional[str] = None
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    mfa: Optional[str] = None  # e.g., TOTP, WebAuthn

class Resource(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: str
    id: Optional[str] = None
    name: Optional[str] = None
    path: Optional[str] = None

class Target(BaseModel):
    model_config = ConfigDict(extra="allow")
    resource: Resource

class AuditEvent(BaseModel):
    """
    Canonical audit event. All timestamps are RFC3339 with UTC 'Z'.
    """
    model_config = ConfigDict(extra="allow")
    schema_version: str = "1.0"
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    type: str = Field(description="API_CALL|AUTH|DATA_ACCESS|CONFIG|SYSTEM|CUSTOM")
    action: str = Field(description="CRUD verb or domain action, e.g., READ/UPDATE/LOGIN")
    outcome: str = Field(default="SUCCESS", description="SUCCESS|DENY|ERROR")
    severity: str = Field(default="INFO", description="INFO|WARN|ERROR|CRITICAL")
    category: str = Field(default="general")
    actor: Actor
    target: Optional[Target] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    source: Dict[str, Any] = Field(default_factory=dict)  # service, version, node, region

class Envelope(BaseModel):
    """
    Wraps event with integrity metadata for downstream sinks.
    """
    model_config = ConfigDict(extra="allow")
    version: int = 1
    event: AuditEvent
    seq: int
    prev_hash_b64: str
    chain_hash_b64: str
    # Optional signature fields
    sig_alg: Optional[str] = None
    sig_hash: Optional[str] = None
    kid: Optional[str] = None
    signature_b64: Optional[str] = None

# -------------------------------------------------------------------------------------
# Utilities
# -------------------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _canonical_json(obj: Any) -> bytes:
    """
    Deterministic JSON for hashing/signing. Not full RFC 8785, but stable.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def _redact(obj: Any, keys: Iterable[str]) -> Any:
    """
    Recursively redact sensitive fields by key name (case-insensitive).
    """
    keyset = {k.lower() for k in keys}
    if isinstance(obj, dict):
        return {k: ("***" if k.lower() in keyset else _redact(v, keyset)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact(v, keyset) for v in obj]
    return obj

# -------------------------------------------------------------------------------------
# Dedup store (Idempotency)
# -------------------------------------------------------------------------------------

class TTLStore:
    def __init__(self, capacity: int = 50000):
        self.capacity = capacity
        self._data: Dict[str, Tuple[int, str]] = {}
        self._lock = asyncio.Lock()

    async def put(self, key: str, ttl: int, value: str = "1") -> None:
        async with self._lock:
            now = int(time.time())
            # evict expired
            to_del = [k for k, (exp, _) in self._data.items() if exp <= now]
            for k in to_del:
                self._data.pop(k, None)
            if len(self._data) >= self.capacity:
                # drop oldest
                oldest = min(self._data.items(), key=lambda kv: kv[1][0])[0]
                self._data.pop(oldest, None)
            self._data[key] = (now + ttl, value)

    async def seen(self, key: str) -> bool:
        async with self._lock:
            item = self._data.get(key)
            return bool(item and item[0] >= int(time.time()))

# -------------------------------------------------------------------------------------
# Signature providers
# -------------------------------------------------------------------------------------

class SignatureProvider:
    """
    Abstract signature provider. Implementations must return (signature_b64, kid, sig_alg, sig_hash).
    """
    async def sign(self, payload: bytes) -> Tuple[str, str, str, str]:  # signature_b64, kid, sig_alg, sig_hash
        raise NotImplementedError

    async def close(self) -> None:
        return None

class HMACSignatureProvider(SignatureProvider):
    def __init__(self, secret: bytes, hash_name: str = "SHA256", kid: Optional[str] = None):
        self.secret = secret
        self.hash_name = hash_name.upper()
        self._kid = kid or _b64u(sha256(secret).digest())

    async def sign(self, payload: bytes) -> Tuple[str, str, str, str]:
        if self.hash_name == "SHA512":
            digest = sha512(self.secret + payload).digest()
        elif self.hash_name == "SHA384":
            digest = sha384(self.secret + payload).digest()
        else:
            digest = sha256(self.secret + payload).digest()
        return _b64u(digest), self._kid, "HMAC", self.hash_name

class AsymmetricSignatureProvider(SignatureProvider):
    """
    Wraps security_core.security.crypto.signer.Signer.
    """
    def __init__(self, signer: Any, hash_name: str = "SHA384"):
        if AsymSigner is None:
            raise RuntimeError("Asymmetric signing is not available (Signer not importable)")
        self.signer: AsymSigner = signer  # type: ignore
        self.hash_name = hash_name.upper()

    async def sign(self, payload: bytes) -> Tuple[str, str, str, str]:
        # Sign canonical payload bytes (already hashed via our signer)
        sig = await self.signer.sign_async(payload)
        return _b64u(sig), self.signer.key_id(), "ASYM", self.hash_name

# -------------------------------------------------------------------------------------
# Sinks
# -------------------------------------------------------------------------------------

class BaseSink:
    async def write_batch(self, envelopes: List[Envelope]) -> None:
        raise NotImplementedError

    async def close(self) -> None:
        return None

class StdoutSink(BaseSink):
    def __init__(self):
        self._lock = asyncio.Lock()

    async def write_batch(self, envelopes: List[Envelope]) -> None:
        line = "\n".join(json.dumps(e.model_dump(), ensure_ascii=False) for e in envelopes) + "\n"
        async with self._lock:
            # delegate to thread to avoid blocking stdout write in large bursts
            await asyncio.to_thread(lambda: print(line, end=""))

class FileSink(BaseSink):
    """
    JSONL with size-based rotation.
    """
    def __init__(self, path: str, rotate_bytes: int = 128 * 1024 * 1024, keep: int = 10, compress: bool = False):
        self.path = Path(path)
        self.rotate_bytes = rotate_bytes
        self.keep = keep
        self.compress = compress
        self._lock = asyncio.Lock()
        self._fp: Optional[Any] = None

    async def _ensure_open(self) -> None:
        if self._fp is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fp = open(self.path, "a", encoding="utf-8")

    def _size(self) -> int:
        try:
            return self.path.stat().st_size
        except Exception:
            return 0

    def _do_rotation_sync(self) -> None:
        try:
            if self._fp:
                self._fp.close()
                self._fp = None
            # rotate: file -> file.1 -> file.2 ...
            for i in reversed(range(1, self.keep)):
                src = f"{self.path}.{i}"
                dst = f"{self.path}.{i+1}"
                if os.path.exists(src):
                    os.replace(src, dst)
            os.replace(self.path, f"{self.path}.1")
            if self.compress:
                import gzip
                with open(f"{self.path}.1", "rb") as rf, gzip.open(f"{self.path}.1.gz", "wb") as wf:
                    wf.writelines(rf)
                os.remove(f"{self.path}.1")
        except FileNotFoundError:
            pass

    async def write_batch(self, envelopes: List[Envelope]) -> None:
        async with self._lock:
            await self._ensure_open()
            data = "".join(json.dumps(e.model_dump(), ensure_ascii=False) + "\n" for e in envelopes)
            await asyncio.to_thread(self._fp.write, data)  # type: ignore
            await asyncio.to_thread(self._fp.flush)        # type: ignore
            if self._size() >= self.rotate_bytes:
                await asyncio.to_thread(self._do_rotation_sync)

    async def close(self) -> None:
        async with self._lock:
            if self._fp:
                await asyncio.to_thread(self._fp.flush)
                await asyncio.to_thread(self._fp.close)
                self._fp = None

class WebhookSink(BaseSink):
    """
    POST NDJSON or JSON array to a webhook.
    """
    def __init__(self, url: str, headers: Optional[Dict[str, str]] = None, ndjson: bool = True, timeout: float = 4.0, retries: int = 2):
        if httpx is None:
            raise RuntimeError("httpx is not available for WebhookSink")
        self.url = url
        self.headers = headers or {"Content-Type": "application/x-ndjson" if ndjson else "application/json"}
        self.ndjson = ndjson
        self.timeout = timeout
        self.retries = retries
        self.client = httpx.AsyncClient(timeout=timeout)

    async def write_batch(self, envelopes: List[Envelope]) -> None:
        payload = "\n".join(json.dumps(e.model_dump(), ensure_ascii=False) for e in envelopes) if self.ndjson \
            else json.dumps([e.model_dump() for e in envelopes], ensure_ascii=False)
        for attempt in range(self.retries + 1):
            try:
                r = await self.client.post(self.url, content=payload, headers=self.headers)
                if r.status_code >= 500:
                    raise RuntimeError(f"webhook server error {r.status_code}")
                return
            except Exception as e:
                if attempt >= self.retries:
                    logger.error("webhook.write.failed attempts=%s err=%s", attempt + 1, e)
                    raise
                await asyncio.sleep(0.2 * (attempt + 1))

    async def close(self) -> None:
        try:
            await self.client.aclose()
        except Exception:
            pass

class KafkaSink(BaseSink):
    """
    Optional Kafka sink. Requires aiokafka.
    Writes JSON envelopes to topic.
    """
    def __init__(self, bootstrap_servers: str, topic: str, client_id: str = "security-core-audit"):
        if AIOKafkaProducer is None:  # type: ignore
            raise RuntimeError("aiokafka is not available for KafkaSink")
        self.topic = topic
        self.producer = AIOKafkaProducer(bootstrap_servers=bootstrap_servers, client_id=client_id)
        self._started = False

    async def write_batch(self, envelopes: List[Envelope]) -> None:
        if not self._started:
            await self.producer.start()
            self._started = True
        for e in envelopes:
            data = json.dumps(e.model_dump(), ensure_ascii=False).encode("utf-8")
            await self.producer.send_and_wait(self.topic, data, key=e.event.event_id.encode())

    async def close(self) -> None:
        if self._started:
            await self.producer.stop()
            self._started = False

# -------------------------------------------------------------------------------------
# Settings
# -------------------------------------------------------------------------------------

class AuditSettings(BaseModel):
    # Pipeline
    max_queue: int = 50000
    batch_size: int = 256
    flush_interval_ms: int = 250
    dedup_ttl_sec: int = 300

    # Redaction
    redact_keys: List[str] = Field(default_factory=lambda: [
        "password", "passwd", "secret", "token", "access_token", "refresh_token",
        "authorization", "cookie", "set-cookie", "private_key"
    ])

    # Integrity
    enable_chain: bool = True
    enable_signing: bool = False
    signing_hmac_secret_b64: Optional[str] = None  # if set -> HMAC mode
    signing_asym: bool = False

    # Seal (periodic summary record persisted to seal file)
    seal_every_ms: int = 15_000
    seal_path: Optional[str] = None

    # Sinks
    stdout_enabled: bool = True
    file_path: Optional[str] = None
    file_rotate_bytes: int = 128 * 1024 * 1024
    file_keep: int = 10
    file_compress: bool = False
    webhook_url: Optional[str] = None
    webhook_headers: Optional[Dict[str, str]] = None
    kafka_bootstrap: Optional[str] = None
    kafka_topic: Optional[str] = None

# -------------------------------------------------------------------------------------
# Audit Trail
# -------------------------------------------------------------------------------------

@dataclass
class _ChainState:
    seq: int = 0
    prev_hash_b64: str = _b64u(b"")  # empty
    last_seal_ts: float = 0.0

class AuditTrail:
    """
    High-throughput, tamper-evident audit pipeline with multi-sink fan-out.
    """
    def __init__(self, settings: AuditSettings, service_info: Optional[Dict[str, Any]] = None,
                 signature_provider: Optional[SignatureProvider] = None):
        self.s = settings
        self.service_info = service_info or {}
        self.queue: asyncio.Queue[AuditEvent] = asyncio.Queue(maxsize=self.s.max_queue)
        self._stop = asyncio.Event()
        self._worker: Optional[asyncio.Task] = None
        self._chain = _ChainState()
        self._dedup = TTLStore()
        self._sinks: List[BaseSink] = []
        self._sig: Optional[SignatureProvider] = signature_provider
        self._metrics = {"enq": 0, "drop": 0, "sent": 0, "errors": 0}

    # ---------- Sinks wiring ----------

    def add_sink(self, sink: BaseSink) -> None:
        self._sinks.append(sink)

    async def _init_default_sinks(self) -> None:
        if self.s.stdout_enabled:
            self.add_sink(StdoutSink())
        if self.s.file_path:
            self.add_sink(FileSink(self.s.file_path, rotate_bytes=self.s.file_rotate_bytes,
                                   keep=self.s.file_keep, compress=self.s.file_compress))
        if self.s.webhook_url:
            if httpx is None:
                logger.warning("WebhookSink skipped: httpx not installed")
            else:
                self.add_sink(WebhookSink(self.s.webhook_url, headers=self.s.webhook_headers))
        if self.s.kafka_bootstrap and self.s.kafka_topic:
            if AIOKafkaProducer is None:
                logger.warning("KafkaSink skipped: aiokafka not installed")
            else:
                self.add_sink(KafkaSink(self.s.kafka_bootstrap, self.s.kafka_topic))

    # ---------- Start/Stop ----------

    async def start(self) -> None:
        # Signature provider autodetect (HMAC vs Asym)
        if self.s.enable_signing and self._sig is None:
            if self.s.signing_hmac_secret_b64:
                secret = base64.b64decode(self.s.signing_hmac_secret_b64 + "===")
                self._sig = HMACSignatureProvider(secret, hash_name="SHA384")
            elif self.s.signing_asym and AsymSigner is not None:
                # You can inject an AsymSigner from outside; if not provided, we cannot auto-create safely.
                logger.warning("enable_signing(asym) set but no signer provided; signing disabled")
                self.s.enable_signing = False
        await self._init_default_sinks()
        self._worker = asyncio.create_task(self._run(), name="audit-trail-worker")
        logger.info("audit.trail.started sinks=%d", len(self._sinks))

    async def stop(self) -> None:
        self._stop.set()
        if self._worker:
            try:
                await self._worker
            except Exception:
                pass
        # Close sinks
        for s in self._sinks:
            try:
                await s.close()
            except Exception:
                pass
        if self._sig:
            try:
                await self._sig.close()
            except Exception:
                pass
        logger.info("audit.trail.stopped sent=%d errors=%d", self._metrics["sent"], self._metrics["errors"])

    # ---------- Emit ----------

    async def emit(self, event: AuditEvent) -> None:
        # Dedup quickly by event_id
        if await self._dedup.seen(event.event_id):
            self._metrics["drop"] += 1
            return
        await self._dedup.put(event.event_id, self.s.dedup_ttl_sec)
        # Enrich source, redact details
        event.source = {**self.service_info, **(event.source or {})}
        if event.details:
            event.details = _redact(event.details, self.s.redact_keys)
        try:
            self.queue.put_nowait(event)
            self._metrics["enq"] += 1
        except asyncio.QueueFull:
            self._metrics["drop"] += 1
            logger.error("audit.queue.full drop event_id=%s", event.event_id)

    # ---------- Worker ----------

    async def _run(self) -> None:
        batch: List[AuditEvent] = []
        flush_deadline = time.time() + (self.s.flush_interval_ms / 1000.0)
        while not self._stop.is_set():
            timeout = max(0.0, flush_deadline - time.time())
            try:
                ev = await asyncio.wait_for(self.queue.get(), timeout=timeout)
                batch.append(ev)
                if len(batch) >= self.s.batch_size:
                    await self._flush(batch)
                    batch = []
                    flush_deadline = time.time() + (self.s.flush_interval_ms / 1000.0)
            except asyncio.TimeoutError:
                if batch:
                    await self._flush(batch)
                    batch = []
                flush_deadline = time.time() + (self.s.flush_interval_ms / 1000.0)
            except Exception as e:
                logger.exception("audit.worker.error %s", e)

        # Drain on stop
        try:
            while not self.queue.empty():
                try:
                    batch.append(self.queue.get_nowait())
                except Exception:
                    break
            if batch:
                await self._flush(batch)
        except Exception:
            pass

    # ---------- Flush ----------

    async def _flush(self, events: List[AuditEvent]) -> None:
        # build envelopes with chain and optional signature
        envelopes: List[Envelope] = []
        for ev in events:
            can = _canonical_json(ev.model_dump())
            ev_hash = sha256(can).digest()
            if self.s.enable_chain:
                prev = base64.urlsafe_b64decode(self._chain.prev_hash_b64 + "===")
                chain = sha256(prev + ev_hash).digest()
            else:
                prev = b""
                chain = ev_hash

            self._chain.seq += 1
            env = Envelope(
                event=ev,
                seq=self._chain.seq,
                prev_hash_b64=_b64u(prev),
                chain_hash_b64=_b64u(chain),
            )

            # optional signature over (seq || prev || chain || event_hash)
            if self.s.enable_signing and self._sig:
                to_sign = _canonical_json({
                    "seq": env.seq,
                    "prev": env.prev_hash_b64,
                    "chain": env.chain_hash_b64,
                    "ev": _b64u(ev_hash),
                    "ts": _now_iso(),
                })
                sig_b64, kid, sig_alg, sig_hash = await self._sig.sign(to_sign)
                env.signature_b64 = sig_b64
                env.kid = kid
                env.sig_alg = sig_alg
                env.sig_hash = sig_hash

            self._chain.prev_hash_b64 = env.chain_hash_b64
            envelopes.append(env)

        # fan-out
        errors = 0
        for sink in self._sinks:
            try:
                await sink.write_batch(envelopes)
            except Exception as e:
                errors += 1
                logger.error("audit.sink.error sink=%s err=%s", sink.__class__.__name__, e)
        self._metrics["sent"] += len(envelopes)
        self._metrics["errors"] += errors

        # periodic seal
        await self._maybe_seal()

    async def _maybe_seal(self) -> None:
        if not self.s.seal_path or self.s.seal_every_ms <= 0:
            return
        now = time.time()
        if now - self._chain.last_seal_ts < (self.s.seal_every_ms / 1000.0):
            return
        self._chain.last_seal_ts = now
        seal = {
            "ts": _now_iso(),
            "seq": self._chain.seq,
            "chain_hash_b64": self._chain.prev_hash_b64,
            "service": self.service_info,
        }
        sig: Optional[Dict[str, str]] = None
        if self.s.enable_signing and self._sig:
            sig_b64, kid, alg, h = await self._sig.sign(_canonical_json(seal))
            sig = {"signature_b64": sig_b64, "kid": kid, "sig_alg": alg, "sig_hash": h}
        record = json.dumps({"seal": seal, "sig": sig}, ensure_ascii=False)
        try:
            await asyncio.to_thread(self._append_seal_sync, record)
        except Exception as e:
            logger.error("audit.seal.write.failed %s", e)

    def _append_seal_sync(self, line: str) -> None:
        p = Path(self.s.seal_path)  # type: ignore
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(line + "\n")

# -------------------------------------------------------------------------------------
# Convenience builder
# -------------------------------------------------------------------------------------

def build_default_trail(service_name: str, version: str, settings: Optional[AuditSettings] = None,
                        signer: Optional[AsymmetricSignatureProvider] = None) -> AuditTrail:
    """
    Helper to create a ready-to-use AuditTrail with standard service info.
    """
    svc = {
        "service": service_name,
        "version": version,
        "node": os.uname().nodename if hasattr(os, "uname") else "unknown",
        "region": os.getenv("REGION"),
        "cluster": os.getenv("CLUSTER"),
    }
    trail = AuditTrail(settings or AuditSettings(), service_info=svc, signature_provider=signer)
    return trail

# -------------------------------------------------------------------------------------
# Example usage (manual test)
# -------------------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    async def main():
        # HMAC signing example (for quick tamper-evidence)
        secret = base64.b64encode(os.urandom(32)).decode()
        s = AuditSettings(
            enable_chain=True,
            enable_signing=True,
            signing_hmac_secret_b64=secret,
            stdout_enabled=True,
            file_path="./_out/audit.jsonl",
            seal_path="./_out/audit.seal",
            kafka_bootstrap=None, kafka_topic=None,
        )
        trail = build_default_trail("security-core", os.getenv("SECURITY_CORE_VERSION", "dev"), s)
        await trail.start()

        ev = AuditEvent(
            type="API_CALL",
            action="UPDATE",
            outcome="SUCCESS",
            category="admin",
            actor=Actor(type="HUMAN", actor_id="alice", roles=["SECURITY_ADMIN"]),
            target=Target(resource=Resource(type="admin", id="policy_reload", name="policy_reload")),
            details={"before": {"mode": "soft"}, "after": {"mode": "strict"}, "token": "shhh"},
            tags=["admin", "policy"]
        )
        await trail.emit(ev)

        # Let the worker flush
        await asyncio.sleep(0.5)
        await trail.stop()

    asyncio.run(main())
