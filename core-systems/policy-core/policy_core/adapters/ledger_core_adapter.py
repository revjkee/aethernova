# policy-core/policy_core/adapters/ledger_core_adapter.py
# Industrial async append-only ledger adapter for NeuroCity/TeslaAI policy-core.
# Features:
#  - Append-only JSONL segments with SHA-256 hash chain (prev_hash -> hash)
#  - Manifest with head index/hash, segment ranges
#  - fsync durability, atomic updates under asyncio.Lock
#  - Idempotency by client-provided key (TTL cache)
#  - Batch append preserving order
#  - Verification of chain integrity (+ optional HMAC)
#  - Snapshot export, segment rotation by size
#  - Optional "anchor" callback every N records
#
# No external dependencies, Python 3.10+.

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import shutil
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    Union,
    runtime_checkable,
)

__all__ = [
    "LedgerEvent",
    "LedgerRecord",
    "LedgerReceipt",
    "VerificationReport",
    "LedgerAdapter",
    "HashChainFileLedger",
]

# ---------- Utilities ----------

def _canon_json(obj: Any) -> str:
    # Stable JSON to feed into hashing/HMAC
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def _sha256_hex(data: Union[str, bytes]) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def _now_ts() -> float:
    return time.time()

# ---------- Data types ----------

@dataclass(frozen=True)
class LedgerEvent:
    # Arbitrary event name, e.g. "policy.decision" | "obligation.success"
    event: str
    # Structured payload (MUST be JSON-serializable)
    data: Mapping[str, Any]
    # Optional deduplication key for idempotency window
    idempotency_key: Optional[str] = None
    # Optional correlation id
    correlation_id: Optional[str] = None
    # Optional severity or importance tag
    severity: Optional[str] = None
    # Optional metadata (tenant, subsystem, actor, etc.)
    meta: Mapping[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class LedgerRecord:
    # Monotonic index starting from 1
    index: int
    # Wall-clock timestamp (seconds)
    ts: float
    # Event content (normalized)
    event: str
    data: Mapping[str, Any]
    meta: Mapping[str, Any]
    severity: Optional[str]
    correlation_id: Optional[str]
    idempotency_key: Optional[str]
    # Chain links
    prev_hash: Optional[str]
    hash: str
    # Optional HMAC over canonical payload (preimage defined below)
    hmac: Optional[str] = None
    # Segment file name this record persisted to (for quick lookups)
    segment: Optional[str] = None

@dataclass(frozen=True)
class LedgerReceipt:
    index: int
    hash: str
    segment: str
    correlation_id: str

@dataclass
class VerificationReport:
    ok: bool
    checked: int
    head_index: int
    head_hash: Optional[str]
    first_broken_index: Optional[int] = None
    reason: Optional[str] = None

# ---------- Adapter protocol ----------

@runtime_checkable
class LedgerAdapter(Protocol):
    async def append(self, event: LedgerEvent) -> LedgerReceipt: ...
    async def batch_append(self, events: Sequence[LedgerEvent]) -> Sequence[LedgerReceipt]: ...
    async def get_by_index(self, index: int) -> Optional[LedgerRecord]: ...
    async def get_by_hash(self, hash_hex: str) -> Optional[LedgerRecord]: ...
    async def verify(self) -> VerificationReport: ...
    async def export_snapshot(self, dst_dir: Union[str, Path]) -> None: ...
    async def close(self) -> None: ...

# ---------- TTL idempotency cache (async-safe) ----------

class _TTLCache:
    def __init__(self, capacity: int = 10000) -> None:
        self._cap = max(1, capacity)
        self._store: Dict[str, Tuple[float, Any]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            item = self._store.get(key)
            if not item:
                return None
            exp, val = item
            if exp and exp < _now_ts():
                self._store.pop(key, None)
                return None
            return val

    async def set(self, key: str, val: Any, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            return
        exp = _now_ts() + ttl_seconds
        async with self._lock:
            if len(self._store) >= self._cap:
                self._store.pop(next(iter(self._store)), None)
            self._store[key] = (exp, val)

# ---------- Hash-chain file ledger implementation ----------

class HashChainFileLedger(LedgerAdapter):
    """
    Append-only ledger based on JSONL segments with SHA-256 hash chain.

    On disk layout:
      base_dir/
        MANIFEST.json
        segments/
          seg-000001.jsonl
          seg-000002.jsonl
          ...

    MANIFEST fields:
      {
        "version": 1,
        "head_index": 42,
        "head_hash": "abc...",
        "segments": [
          {"file": "seg-000001.jsonl", "start": 1, "end": 200},
          {"file": "seg-000002.jsonl", "start": 201, "end": 420}
        ]
      }
    """

    def __init__(
        self,
        base_dir: Union[str, Path],
        *,
        segment_max_bytes: int = 8 * 1024 * 1024,
        fsync_on_write: bool = True,
        idempotency_ttl_seconds: int = 300,
        idem_cache_capacity: int = 20000,
        hmac_secret: Optional[bytes] = None,
        anchor_every: Optional[int] = None,
        anchor_callback: Optional[Callable[[int, str], Awaitable[None]]] = None,
    ) -> None:
        self.base_dir = Path(base_dir)
        self.seg_dir = self.base_dir / "segments"
        self.manifest_path = self.base_dir / "MANIFEST.json"
        self.seg_dir.mkdir(parents=True, exist_ok=True)
        self.fsync_on_write = fsync_on_write
        self.segment_max_bytes = max(1024, int(segment_max_bytes))
        self.hmac_secret = hmac_secret
        self.anchor_every = anchor_every if anchor_every and anchor_every > 0 else None
        self.anchor_callback = anchor_callback

        self._lock = asyncio.Lock()
        self._idempotency = _TTLCache(capacity=idem_cache_capacity)
        self._idempotency_ttl = max(0, int(idempotency_ttl_seconds))

        # in-memory head state
        self._head_index: int = 0
        self._head_hash: Optional[str] = None
        self._segments: List[Dict[str, Any]] = []  # [{"file": name, "start": int, "end": int}]
        self._current_seg: Optional[Path] = None

        # initialize or load manifest
        self._load_or_init_manifest()

    # ----- Public API -----

    async def append(self, event: LedgerEvent) -> LedgerReceipt:
        async with self._lock:
            # idempotency short-circuit
            if event.idempotency_key:
                key = self._idem_key(event.idempotency_key)
                cached = await self._idempotency.get(key)
                if cached:
                    return cached

            rec = await self._build_record(event)
            seg_path = await self._ensure_segment_ready()
            await self._append_record_to_segment(seg_path, rec)
            self._advance_head(rec, seg_path.name)
            await self._persist_manifest()

            receipt = LedgerReceipt(index=rec.index, hash=rec.hash, segment=seg_path.name,
                                    correlation_id=rec.correlation_id or "")
            if event.idempotency_key and self._idempotency_ttl > 0:
                await self._idempotency.set(self._idem_key(event.idempotency_key), receipt, self._idempotency_ttl)

            # optional anchor
            if self.anchor_every and self.anchor_callback and rec.index % self.anchor_every == 0:
                # fire-and-forget; no impact on main path
                asyncio.create_task(self.anchor_callback(rec.index, rec.hash))

            return receipt

    async def batch_append(self, events: Sequence[LedgerEvent]) -> Sequence[LedgerReceipt]:
        if not events:
            return []
        receipts: List[LedgerReceipt] = []
        async with self._lock:
            seg_path = await self._ensure_segment_ready()
            for ev in events:
                if ev.idempotency_key:
                    key = self._idem_key(ev.idempotency_key)
                    cached = await self._idempotency.get(key)
                    if cached:
                        receipts.append(cached)
                        continue

                rec = await self._build_record(ev)
                await self._append_record_to_segment(seg_path, rec)
                self._advance_head(rec, seg_path.name)
                # rotate if needed after each write
                if seg_path.stat().st_size >= self.segment_max_bytes:
                    await self._persist_manifest()
                    seg_path = await self._roll_segment()

                receipt = LedgerReceipt(index=rec.index, hash=rec.hash, segment=seg_path.name,
                                        correlation_id=rec.correlation_id or "")
                receipts.append(receipt)
                if ev.idempotency_key and self._idempotency_ttl > 0:
                    await self._idempotency.set(self._idem_key(ev.idempotency_key), receipt, self._idempotency_ttl)

            await self._persist_manifest()

            # optional anchor after batch
            if self.anchor_every and self.anchor_callback and self._head_index % self.anchor_every == 0:
                asyncio.create_task(self.anchor_callback(self._head_index, self._head_hash or ""))

        return receipts

    async def get_by_index(self, index: int) -> Optional[LedgerRecord]:
        if index <= 0:
            return None
        # quick range lookup
        seg = self._find_segment_by_index(index)
        if not seg:
            return None
        seg_path = self.seg_dir / seg["file"]
        async for rec in self._iter_segment(seg_path):
            if rec.index == index:
                return rec
        return None

    async def get_by_hash(self, hash_hex: str) -> Optional[LedgerRecord]:
        for seg in self._segments:
            seg_path = self.seg_dir / seg["file"]
            async for rec in self._iter_segment(seg_path):
                if rec.hash == hash_hex:
                    return rec
        return None

    async def verify(self) -> VerificationReport:
        expected_prev: Optional[str] = None
        expected_index = 0
        checked = 0
        try:
            for seg in self._segments:
                seg_path = self.seg_dir / seg["file"]
                async for rec in self._iter_segment(seg_path):
                    expected_index += 1
                    if rec.index != expected_index:
                        return VerificationReport(
                            ok=False, checked=checked, head_index=self._head_index, head_hash=self._head_hash,
                            first_broken_index=rec.index, reason="index_gap_or_mismatch"
                        )
                    preimage = self._record_preimage(rec)
                    if _sha256_hex(preimage) != rec.hash:
                        return VerificationReport(
                            ok=False, checked=checked, head_index=self._head_index, head_hash=self._head_hash,
                            first_broken_index=rec.index, reason="hash_mismatch"
                        )
                    if rec.prev_hash != expected_prev:
                        return VerificationReport(
                            ok=False, checked=checked, head_index=self._head_index, head_hash=self._head_hash,
                            first_broken_index=rec.index, reason="prev_hash_mismatch"
                        )
                    # HMAC check if configured
                    if self.hmac_secret:
                        mac = hmac.new(self.hmac_secret, preimage.encode("utf-8"), hashlib.sha256).hexdigest()
                        if rec.hmac != mac:
                            return VerificationReport(
                                ok=False, checked=checked, head_index=self._head_index, head_hash=self._head_hash,
                                first_broken_index=rec.index, reason="hmac_mismatch"
                            )
                    expected_prev = rec.hash
                    checked += 1
            return VerificationReport(ok=True, checked=checked, head_index=self._head_index, head_hash=self._head_hash)
        except Exception as exc:
            return VerificationReport(ok=False, checked=checked, head_index=self._head_index, head_hash=self._head_hash,
                                      first_broken_index=expected_index + 1, reason=str(exc))

    async def export_snapshot(self, dst_dir: Union[str, Path]) -> None:
        dst = Path(dst_dir)
        dst.mkdir(parents=True, exist_ok=True)
        # flush manifest to ensure consistency
        async with self._lock:
            await self._persist_manifest()
        # copy manifest and all segments
        shutil.copy2(self.manifest_path, dst / "MANIFEST.json")
        dst_seg = dst / "segments"
        dst_seg.mkdir(parents=True, exist_ok=True)
        for seg in self._segments:
            shutil.copy2(self.seg_dir / seg["file"], dst_seg / seg["file"])

    async def close(self) -> None:
        # nothing to close explicitly
        return

    # ----- Internals -----

    def _load_or_init_manifest(self) -> None:
        if self.manifest_path.exists():
            with self.manifest_path.open("r", encoding="utf-8") as f:
                mf = json.load(f)
            self._segments = list(mf.get("segments", []))
            self._head_index = int(mf.get("head_index", 0))
            self._head_hash = mf.get("head_hash")
            # pick current segment (last)
            if self._segments:
                self._current_seg = self.seg_dir / self._segments[-1]["file"]
            else:
                self._current_seg = None
        else:
            self._segments = []
            self._head_index = 0
            self._head_hash = None
            self._current_seg = None
            # create first empty segment
            self._current_seg = self._new_segment_path(1)
            self._segments.append({"file": self._current_seg.name, "start": 1, "end": 0})
            self._persist_manifest_sync()

    async def _ensure_segment_ready(self) -> Path:
        if not self._current_seg or not self._current_seg.exists():
            # roll based on head_index
            next_start = self._head_index + 1 if self._head_index > 0 else 1
            self._current_seg = self._new_segment_path(next_start)
            self._segments.append({"file": self._current_seg.name, "start": next_start, "end": self._head_index})
            await self._persist_manifest()
        # rotate if current file oversized
        if self._current_seg.stat().st_size >= self.segment_max_bytes:
            return await self._roll_segment()
        return self._current_seg

    async def _roll_segment(self) -> Path:
        next_start = self._head_index + 1
        self._current_seg = self._new_segment_path(next_start)
        self._segments.append({"file": self._current_seg.name, "start": next_start, "end": self._head_index})
        await self._persist_manifest()
        return self._current_seg

    def _new_segment_path(self, start_index: int) -> Path:
        seq = len(self._segments) + 1
        name = f"seg-{seq:06d}.jsonl"
        return self.seg_dir / name

    async def _build_record(self, event: LedgerEvent) -> LedgerRecord:
        idx = self._head_index + 1
        ts = _now_ts()
        corr = event.correlation_id or str(uuid.uuid4())
        # Preimage excludes dynamic fields (hash/hmac/segment)
        base = {
            "index": idx,
            "ts": ts,
            "event": event.event,
            "data": event.data,
            "meta": event.meta,
            "severity": event.severity,
            "correlation_id": corr,
            "idempotency_key": event.idempotency_key,
            "prev_hash": self._head_hash,
        }
        preimage = _canon_json(base)
        h = _sha256_hex(preimage)
        mac: Optional[str] = None
        if self.hmac_secret:
            mac = hmac.new(self.hmac_secret, preimage.encode("utf-8"), hashlib.sha256).hexdigest()
        return LedgerRecord(
            index=idx,
            ts=ts,
            event=event.event,
            data=event.data,
            meta=event.meta,
            severity=event.severity,
            correlation_id=corr,
            idempotency_key=event.idempotency_key,
            prev_hash=self._head_hash,
            hash=h,
            hmac=mac,
            segment=None,
        )

    async def _append_record_to_segment(self, seg_path: Path, rec: LedgerRecord) -> None:
        # Append record line as JSON; then fsync
        obj = asdict(rec)
        obj["segment"] = seg_path.name
        line = _canon_json(obj) + "\n"
        await asyncio.to_thread(self._write_and_fsync, seg_path, line)

    def _write_and_fsync(self, seg_path: Path, line: str) -> None:
        with seg_path.open("a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            if self.fsync_on_write:
                os.fsync(f.fileno())

    def _advance_head(self, rec: LedgerRecord, seg_name: str) -> None:
        self._head_index = rec.index
        self._head_hash = rec.hash
        rec.segment = seg_name
        # update last segment end index
        if self._segments:
            self._segments[-1]["end"] = self._head_index

    async def _persist_manifest(self) -> None:
        await asyncio.to_thread(self._persist_manifest_sync)

    def _persist_manifest_sync(self) -> None:
        tmp = self.manifest_path.with_suffix(".json.tmp")
        mf = {
            "version": 1,
            "head_index": self._head_index,
            "head_hash": self._head_hash,
            "segments": self._segments,
        }
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(mf, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        tmp.replace(self.manifest_path)

    def _find_segment_by_index(self, index: int) -> Optional[Dict[str, Any]]:
        for seg in self._segments:
            start = int(seg["start"])
            end = int(seg["end"])
            # end may be 0 for the very first empty manifest; handle inclusive range
            if end == 0:
                if index == start:
                    return seg
            elif start <= index <= end:
                return seg
        return None

    async def _iter_segment(self, seg_path: Path):
        # Async generator over records in a segment
        def _read_lines() -> Iterable[str]:
            if not seg_path.exists():
                return []
            with seg_path.open("r", encoding="utf-8") as f:
                return list(f)
        lines = await asyncio.to_thread(_read_lines)
        for ln in lines:
            ln = ln.strip()
            if not ln:
                continue
            try:
                obj = json.loads(ln)
                rec = LedgerRecord(
                    index=int(obj["index"]),
                    ts=float(obj["ts"]),
                    event=str(obj["event"]),
                    data=obj.get("data", {}),
                    meta=obj.get("meta", {}),
                    severity=obj.get("severity"),
                    correlation_id=obj.get("correlation_id"),
                    idempotency_key=obj.get("idempotency_key"),
                    prev_hash=obj.get("prev_hash"),
                    hash=obj["hash"],
                    hmac=obj.get("hmac"),
                    segment=obj.get("segment"),
                )
                yield rec
            except Exception:
                # Skip malformed lines
                continue

    def _record_preimage(self, rec: LedgerRecord) -> str:
        base = {
            "index": rec.index,
            "ts": rec.ts,
            "event": rec.event,
            "data": rec.data,
            "meta": rec.meta,
            "severity": rec.severity,
            "correlation_id": rec.correlation_id,
            "idempotency_key": rec.idempotency_key,
            "prev_hash": rec.prev_hash,
        }
        return _canon_json(base)

    def _idem_key(self, key: str) -> str:
        return f"idem:{key}"
