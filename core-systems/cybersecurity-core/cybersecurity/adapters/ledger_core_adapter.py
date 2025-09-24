# cybersecurity-core/cybersecurity/adapters/ledger_core_adapter.py
# -*- coding: utf-8 -*-
"""
Ledger Core Adapter for append-only, integrity-protected security audit logs.

Features:
- Append-only event recording with SHA-256 hash chaining per partition/tenant
- Optional cryptographic signatures:
    * Ed25519 (PyNaCl preferred, or cryptography if wired)
    * HMAC-SHA256 fallback
- Idempotency by event_id and Idempotency-Key
- Strict Pydantic models (v2 preferred; v1 compatible)
- Async API; structured logging; optional OpenTelemetry spans
- Pluggable backends via Protocol: Memory (tests) and File (NDJSON, append-only with locking)
- Chain verification, range proofs (linear), NDJSON export/import

Dependencies:
    pydantic>=1.10 (v2 supported)
Optional:
    pynacl (for Ed25519 signatures)
    opentelemetry-api (tracing)

Security notes:
- File backend writes canonical NDJSON lines and a sidecar head file per partition.
- Hash chain covers canonical JSON of record content excluding "hash" and "signature".
- When signatures are enabled, signature covers the same canonical content and prev_hash.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import logging
import os
import platform
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple

# --- Pydantic v2/v1 compatibility --------------------------------------------
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

# --- Optional Ed25519 via PyNaCl ---------------------------------------------
_ED25519_AVAILABLE = False
try:
    from nacl import signing  # type: ignore
    from nacl import exceptions as nacl_exceptions  # type: ignore
    _ED25519_AVAILABLE = True
except Exception:  # pragma: no cover
    signing = None  # type: ignore
    nacl_exceptions = None  # type: ignore

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger("ledger_core_adapter")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logger.addHandler(_h)
    logger.setLevel(os.getenv("LEDGER_LOG_LEVEL", "INFO"))

# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _canonical_json(obj: Mapping[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

class LedgerRecord(BaseModel):
    # Identity and context
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant: str = Field(default="default", min_length=1, max_length=128)
    timestamp: datetime = Field(default_factory=now_utc)
    actor: Optional[str] = Field(default=None, max_length=256)
    action: str = Field(min_length=1, max_length=256)  # e.g. "iam.user.create"
    resource: Optional[str] = Field(default=None, max_length=256)  # e.g. "user"
    resource_id: Optional[str] = Field(default=None, max_length=256)
    severity: Optional[str] = Field(default=None, regex=r"^(low|medium|high|critical)$")
    correlation_id: Optional[str] = Field(default=None, max_length=128)
    tags: List[str] = Field(default_factory=list)
    data: Dict[str, Any] = Field(default_factory=dict)

    # Integrity fields
    prev_hash: Optional[str] = None   # hex string
    hash: Optional[str] = None        # hex string
    sig_alg: Optional[str] = None     # "ed25519" or "hmac-sha256"
    key_id: Optional[str] = None
    signature: Optional[str] = None   # base64

    schema_version: int = 1

    def content_for_hash(self) -> Dict[str, Any]:
        """
        Return mapping that is covered by hash/signature.
        Note: excludes 'hash', 'signature' fields.
        """
        return {
            "event_id": self.event_id,
            "tenant": self.tenant,
            "timestamp": self.timestamp.isoformat(),
            "actor": self.actor,
            "action": self.action,
            "resource": self.resource,
            "resource_id": self.resource_id,
            "severity": self.severity,
            "correlation_id": self.correlation_id,
            "tags": self.tags,
            "data": self.data,
            "prev_hash": self.prev_hash,
            "schema_version": self.schema_version,
        }

class WriteResult(BaseModel):
    event_id: str
    hash: str
    signature: Optional[str] = None

# -----------------------------------------------------------------------------
# Signers
# -----------------------------------------------------------------------------
class Signer(Protocol):
    alg: str
    key_id: str
    def sign(self, payload: bytes) -> bytes: ...
    def verify(self, payload: bytes, signature: bytes) -> bool: ...

class HMACSigner:
    alg = "hmac-sha256"
    def __init__(self, secret: bytes, key_id: str = "hmac-default") -> None:
        self._secret = secret
        self.key_id = key_id

    def sign(self, payload: bytes) -> bytes:
        import hmac
        return hmac.new(self._secret, payload, hashlib.sha256).digest()

    def verify(self, payload: bytes, signature: bytes) -> bool:
        import hmac
        digest = hmac.new(self._secret, payload, hashlib.sha256).digest()
        return hmac.compare_digest(digest, signature)

class Ed25519Signer:
    alg = "ed25519"
    def __init__(self, private_key_b64: str, key_id: str = "ed25519-default") -> None:
        if not _ED25519_AVAILABLE:
            raise RuntimeError("PyNaCl is not installed for Ed25519")
        self._sk = signing.SigningKey(base64.b64decode(private_key_b64))
        self._vk = self._sk.verify_key
        self.key_id = key_id

    def sign(self, payload: bytes) -> bytes:
        s = self._sk.sign(payload)
        return bytes(s.signature)

    def verify(self, payload: bytes, signature: bytes) -> bool:
        try:
            self._vk.verify(payload, signature)
            return True
        except Exception:
            return False

# -----------------------------------------------------------------------------
# Backend protocol
# -----------------------------------------------------------------------------
class LedgerBackend(Protocol):
    async def get_by_id(self, tenant: str, event_id: str) -> Optional[LedgerRecord]: ...
    async def get_head(self, tenant: str) -> Optional[LedgerRecord]: ...
    async def append(self, record: LedgerRecord) -> None: ...
    async def append_batch(self, records: Sequence[LedgerRecord]) -> None: ...
    async def iter_range(
        self, tenant: str, *, start_ts: Optional[datetime] = None, end_ts: Optional[datetime] = None
    ) -> Iterable[LedgerRecord]: ...

# -----------------------------------------------------------------------------
# Memory backend (for tests)
# -----------------------------------------------------------------------------
class MemoryLedgerBackend:
    def __init__(self) -> None:
        self._store: Dict[str, List[LedgerRecord]] = {}  # tenant -> list
        self._index: Dict[Tuple[str, str], LedgerRecord] = {}

    async def get_by_id(self, tenant: str, event_id: str) -> Optional[LedgerRecord]:
        return self._index.get((tenant, event_id))

    async def get_head(self, tenant: str) -> Optional[LedgerRecord]:
        lst = self._store.get(tenant) or []
        return lst[-1] if lst else None

    async def append(self, record: LedgerRecord) -> None:
        self._store.setdefault(record.tenant, []).append(record)
        self._index[(record.tenant, record.event_id)] = record

    async def append_batch(self, records: Sequence[LedgerRecord]) -> None:
        for r in records:
            await self.append(r)

    async def iter_range(
        self, tenant: str, *, start_ts: Optional[datetime] = None, end_ts: Optional[datetime] = None
    ) -> Iterable[LedgerRecord]:
        lst = self._store.get(tenant) or []
        for r in lst:
            if start_ts and r.timestamp < start_ts:
                continue
            if end_ts and r.timestamp > end_ts:
                continue
            yield r

# -----------------------------------------------------------------------------
# File backend (append-only NDJSON with sidecar head)
# -----------------------------------------------------------------------------
class FileLedgerBackend:
    """
    Stores ledger as NDJSON per tenant:
      <base_dir>/<tenant>.ndjson
    Head hash cached in sidecar:
      <base_dir>/<tenant>.head
    Index by event_id is not memory-resident; simple scan used for get_by_id (OK for moderate journal sizes).
    """
    def __init__(self, base_dir: str) -> None:
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)
        self._locks: Dict[str, asyncio.Lock] = {}

    def _lock(self, tenant: str) -> asyncio.Lock:
        self._locks.setdefault(tenant, asyncio.Lock())
        return self._locks[tenant]

    def _path(self, tenant: str) -> str:
        safe = tenant.replace("/", "_")
        return os.path.join(self.base_dir, f"{safe}.ndjson")

    def _head_path(self, tenant: str) -> str:
        safe = tenant.replace("/", "_")
        return os.path.join(self.base_dir, f"{safe}.head")

    async def _write_line_atomic(self, path: str, line: bytes) -> None:
        # Use synchronous os.open/os.write in a thread to ensure single call write.
        def _do():
            fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o640)
            try:
                os.write(fd, line)
                os.fsync(fd)
            finally:
                os.close(fd)
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _do)

    async def _read_head(self, tenant: str) -> Optional[str]:
        path = self._head_path(tenant)
        if not os.path.exists(path):
            return None
        def _do() -> Optional[str]:
            try:
                with open(path, "rt", encoding="utf-8") as f:
                    s = f.read().strip()
                    return s or None
            except Exception:
                return None
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _do)

    async def _write_head(self, tenant: str, head_hash: str) -> None:
        path = self._head_path(tenant)
        def _do():
            tmp = f"{path}.tmp"
            with open(tmp, "wt", encoding="utf-8") as f:
                f.write(head_hash + "\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _do)

    async def get_head(self, tenant: str) -> Optional[LedgerRecord]:
        head_hash = await self._read_head(tenant)
        if head_hash is None:
            # Maybe recompute from file end
            path = self._path(tenant)
            if not os.path.exists(path):
                return None
            rec = None
            async for r in self._iter_file(tenant):
                rec = r
            if rec is not None:
                await self._write_head(tenant, rec.hash or "")
            return rec
        # Find by scanning from end (simple approach)
        last = None
        async for r in self._iter_file(tenant):
            last = r
        return last

    async def get_by_id(self, tenant: str, event_id: str) -> Optional[LedgerRecord]:
        async for r in self._iter_file(tenant):
            if r.event_id == event_id:
                return r
        return None

    async def append(self, record: LedgerRecord) -> None:
        async with self._lock(record.tenant):
            line = (json.dumps(record.dict(), ensure_ascii=False, separators=(",", ")) + "\n").encode("utf-8")
            await self._write_line_atomic(self._path(record.tenant), line)
            if record.hash:
                await self._write_head(record.tenant, record.hash)

    async def append_batch(self, records: Sequence[LedgerRecord]) -> None:
        if not records:
            return
        tenant = records[0].tenant
        async with self._lock(tenant):
            buf = bytearray()
            for r in records:
                buf.extend((json.dumps(r.dict(), ensure_ascii=False, separators=(",", ")) + "\n").encode("utf-8"))
            await self._write_line_atomic(self._path(tenant), bytes(buf))
            last = records[-1]
            if last.hash:
                await self._write_head(tenant, last.hash)

    async def iter_range(
        self, tenant: str, *, start_ts: Optional[datetime] = None, end_ts: Optional[datetime] = None
    ) -> Iterable[LedgerRecord]:
        async for r in self._iter_file(tenant):
            if start_ts and r.timestamp < start_ts:
                continue
            if end_ts and r.timestamp > end_ts:
                continue
            yield r

    async def _iter_file(self, tenant: str) -> Iterable[LedgerRecord]:
        path = self._path(tenant)
        if not os.path.exists(path):
            return
        loop = asyncio.get_running_loop()

        def _read_lines() -> List[str]:
            try:
                with open(path, "rt", encoding="utf-8") as f:
                    return f.readlines()
            except FileNotFoundError:
                return []
        lines = await loop.run_in_executor(None, _read_lines)
        for ln in lines:
            ln = ln.strip()
            if not ln:
                continue
            try:
                obj = json.loads(ln)
                # pydantic parse
                rec = LedgerRecord.model_validate(obj) if PydanticV2 else LedgerRecord.parse_obj(obj)  # type: ignore
                yield rec
            except Exception:
                continue

# -----------------------------------------------------------------------------
# Adapter (core)
# -----------------------------------------------------------------------------
@dataclass
class LedgerConfig:
    enable_signature: bool = False
    signer: Optional[Signer] = None
    enforce_idempotency: bool = True
    enable_tracing: bool = True

class LedgerCoreAdapter:
    """
    High-level orchestrator around a LedgerBackend:
      - builds hash chain
      - signs (optional)
      - enforces idempotency
      - verifies chain
    """
    def __init__(self, backend: LedgerBackend, config: Optional[LedgerConfig] = None) -> None:
        self.backend = backend
        self.config = config or LedgerConfig()
        self._tracing = bool(self.config.enable_tracing and _tracer is not None)

    # --- Write API ------------------------------------------------------------
    async def record(
        self,
        *,
        tenant: str,
        action: str,
        actor: Optional[str] = None,
        resource: Optional[str] = None,
        resource_id: Optional[str] = None,
        data: Optional[Mapping[str, Any]] = None,
        severity: Optional[str] = None,
        correlation_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
        event_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> WriteResult:
        span = _tracer.start_as_current_span("ledger.record") if self._tracing else None
        if span:  # pragma: no cover
            span.__enter__()

        try:
            eid = event_id or idempotency_key or str(uuid.uuid4())
            if self.config.enforce_idempotency:
                existing = await self.backend.get_by_id(tenant, eid)
                if existing:
                    return WriteResult(event_id=eid, hash=existing.hash or "", signature=existing.signature)

            head = await self.backend.get_head(tenant)
            prev_hash = head.hash if head else None

            rec = LedgerRecord(
                event_id=eid,
                tenant=tenant,
                timestamp=timestamp or now_utc(),
                actor=actor,
                action=action,
                resource=resource,
                resource_id=resource_id,
                severity=severity,
                correlation_id=correlation_id,
                tags=tags or [],
                data=dict(data or {}),
                prev_hash=prev_hash,
            )

            payload = _canonical_json(rec.content_for_hash())
            h = hashlib.sha256(payload).hexdigest()
            rec.hash = h

            if self.config.enable_signature and self.config.signer:
                sig_bytes = self.config.signer.sign(payload)
                rec.signature = base64.b64encode(sig_bytes).decode("ascii")
                rec.sig_alg = self.config.signer.alg
                rec.key_id = self.config.signer.key_id

            await self.backend.append(rec)
            return WriteResult(event_id=rec.event_id, hash=rec.hash, signature=rec.signature)
        finally:
            if span:  # pragma: no cover
                span.__exit__(None, None, None)

    async def record_batch(
        self,
        *,
        tenant: str,
        events: Sequence[Mapping[str, Any]],
        idempotency: bool = True,
    ) -> List[WriteResult]:
        """
        events: sequence of dicts with keys accepted by record() except tenant.
        Batch preserves order for hash chaining. Idempotency checks per event_id if enabled.
        """
        span = _tracer.start_as_current_span("ledger.record_batch") if self._tracing else None
        if span:  # pragma: no cover
            span.__enter__()

        try:
            results: List[WriteResult] = []
            head = await self.backend.get_head(tenant)
            prev_hash = head.hash if head else None
            batch: List[LedgerRecord] = []

            for ev in events:
                eid = ev.get("event_id") or ev.get("idempotency_key") or str(uuid.uuid4())
                if idempotency and self.config.enforce_idempotency:
                    existing = await self.backend.get_by_id(tenant, eid)
                    if existing:
                        results.append(WriteResult(event_id=eid, hash=existing.hash or "", signature=existing.signature))
                        prev_hash = existing.hash or prev_hash
                        continue

                rec = LedgerRecord(
                    event_id=eid,
                    tenant=tenant,
                    timestamp=ev.get("timestamp") or now_utc(),
                    actor=ev.get("actor"),
                    action=ev["action"],
                    resource=ev.get("resource"),
                    resource_id=ev.get("resource_id"),
                    severity=ev.get("severity"),
                    correlation_id=ev.get("correlation_id"),
                    tags=list(ev.get("tags") or []),
                    data=dict(ev.get("data") or {}),
                    prev_hash=prev_hash,
                )
                payload = _canonical_json(rec.content_for_hash())
                rec.hash = hashlib.sha256(payload).hexdigest()

                if self.config.enable_signature and self.config.signer:
                    sig_bytes = self.config.signer.sign(payload)
                    rec.signature = base64.b64encode(sig_bytes).decode("ascii")
                    rec.sig_alg = self.config.signer.alg
                    rec.key_id = self.config.signer.key_id

                batch.append(rec)
                prev_hash = rec.hash

            if batch:
                await self.backend.append_batch(batch)
                for r in batch:
                    results.append(WriteResult(event_id=r.event_id, hash=r.hash or "", signature=r.signature))
            return results
        finally:
            if span:  # pragma: no cover
                span.__exit__(None, None, None)

    # --- Verification API -----------------------------------------------------
    async def verify_chain(
        self,
        tenant: str,
        *,
        start_ts: Optional[datetime] = None,
        end_ts: Optional[datetime] = None,
        verify_signatures: bool = False,
        signer: Optional[Signer] = None,
    ) -> Tuple[bool, Optional[str], int]:
        """
        Returns (ok, error_msg, checked_count).
        Verifies hash continuity and (optionally) signatures over canonical payloads.
        """
        signer = signer or self.config.signer
        prev_hash = None
        count = 0
        async for rec in self.backend.iter_range(tenant, start_ts=start_ts, end_ts=end_ts):
            payload = _canonical_json(rec.content_for_hash())
            calc_hash = hashlib.sha256(payload).hexdigest()
            if rec.hash != calc_hash:
                return False, f"Hash mismatch at event {rec.event_id}", count
            if rec.prev_hash != prev_hash:
                # First record allowed to have prev_hash None
                if count != 0:
                    return False, f"Broken chain at event {rec.event_id}", count
            if verify_signatures:
                if not rec.signature or not rec.sig_alg or not rec.key_id:
                    return False, f"Missing signature at event {rec.event_id}", count
                if not signer or signer.alg != rec.sig_alg:
                    return False, f"Signer mismatch for event {rec.event_id}", count
                sig_bytes = base64.b64decode(rec.signature)
                if not signer.verify(payload, sig_bytes):
                    return False, f"Signature invalid at event {rec.event_id}", count
            prev_hash = rec.hash
            count += 1
        return True, None, count

    # --- Export/Import --------------------------------------------------------
    async def export_ndjson(self, tenant: str) -> bytes:
        """
        Export whole tenant ledger as NDJSON bytes (not streaming for simplicity).
        """
        lines: List[str] = []
        async for rec in self.backend.iter_range(tenant):
            lines.append(json.dumps(rec.dict(), ensure_ascii=False, separators=(",", ")) + "\n")
        return "".join(lines).encode("utf-8")

    async def import_ndjson(self, tenant: str, data: bytes, *, trust_hashes: bool = False) -> int:
        """
        Import NDJSON dump. If trust_hashes=False, hashes/signatures are recomputed.
        """
        text = data.decode("utf-8", errors="ignore")
        batch: List[LedgerRecord] = []
        head = await self.backend.get_head(tenant)
        prev_hash = head.hash if head else None
        count = 0
        for ln in text.splitlines():
            if not ln.strip():
                continue
            try:
                obj = json.loads(ln)
                rec = LedgerRecord.model_validate(obj) if PydanticV2 else LedgerRecord.parse_obj(obj)  # type: ignore
                if rec.tenant != tenant:
                    # normalize to target tenant if needed
                    rec.tenant = tenant
                if not trust_hashes:
                    rec.prev_hash = prev_hash
                    payload = _canonical_json(rec.content_for_hash())
                    rec.hash = hashlib.sha256(payload).hexdigest()
                    if self.config.enable_signature and self.config.signer:
                        sig_bytes = self.config.signer.sign(payload)
                        rec.signature = base64.b64encode(sig_bytes).decode("ascii")
                        rec.sig_alg = self.config.signer.alg
                        rec.key_id = self.config.signer.key_id
                prev_hash = rec.hash
                batch.append(rec)
                count += 1
            except Exception:
                continue
        if batch:
            await self.backend.append_batch(batch)
        return count

# -----------------------------------------------------------------------------
# Convenience factories
# -----------------------------------------------------------------------------
def make_hmac_signer(secret: str, key_id: str = "hmac-default") -> HMACSigner:
    return HMACSigner(secret.encode("utf-8"), key_id=key_id)

def make_ed25519_signer(private_key_b64: str, key_id: str = "ed25519-default") -> Ed25519Signer:
    return Ed25519Signer(private_key_b64, key_id=key_id)

# -----------------------------------------------------------------------------
# __all__
# -----------------------------------------------------------------------------
__all__ = [
    "LedgerRecord",
    "WriteResult",
    "Signer",
    "HMACSigner",
    "Ed25519Signer",
    "LedgerBackend",
    "MemoryLedgerBackend",
    "FileLedgerBackend",
    "LedgerConfig",
    "LedgerCoreAdapter",
    "make_hmac_signer",
    "make_ed25519_signer",
]
