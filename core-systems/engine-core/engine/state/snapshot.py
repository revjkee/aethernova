# engine-core/engine/state/snapshot.py
"""
Industrial-grade deterministic snapshot/delta system.

Key features:
- Canonical, stable, language-agnostic encoding for dict/list/number/bytes/str
- Snapshot container with TOC (table-of-contents) and named sections
- Optional zlib compression per-chunk; CRC32 per-chunk integrity
- Global 64-bit FNV-1a digest; optional BLAKE2b-128 mixing
- Delta encoder: XOR/copy patch between two snapshots (per-section)
- Delta applier to reconstruct new snapshot from base + patch
- SnapshotStore with memory/time budgets; LRU-like pruning
- Deterministic helpers to serialize ECS-like worlds and components

No external dependencies. Uses only Python standard library.
"""

from __future__ import annotations

from dataclasses import dataclass, field, is_dataclass, asdict
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple
import struct
import zlib
import time
import hashlib

# =========================
# Canonical encoding (shared with other subsystems)
# =========================

FNV64_OFFSET = 0xcbf29ce484222325
FNV64_PRIME  = 0x100000001b3

def fnv1a64(data: bytes, seed: int = FNV64_OFFSET) -> int:
    h = seed & 0xFFFFFFFFFFFFFFFF
    for b in data:
        h ^= b
        h = (h * FNV64_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h

def _uvarint(n: int) -> bytes:
    if n < 0:
        raise ValueError("uvarint requires non-negative")
    out = bytearray()
    x = n
    while True:
        b = x & 0x7F
        x >>= 7
        if x:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)

def _svarint(n: int) -> bytes:
    # zigzag + uvarint
    u = (n << 1) ^ (n >> 63)
    return _uvarint(u & 0xFFFFFFFFFFFFFFFF)

def canonical_encode(obj: Any) -> bytes:
    """
    Compact deterministic encoding:
      N|null, T|true, F|false,
      I <len><ascii>, D <8 bytes BE>, S <len><utf8>, B <len><bytes>,
      L <len><items...>, M <len><sorted(k,v)...>
    """
    t = type(obj)
    if obj is None:
        return b"N"
    if t is bool:
        return b"T" if obj else b"F"
    if t is int:
        b = str(int(obj)).encode("ascii")
        return b"I" + _uvarint(len(b)) + b
    if t is float:
        return b"D" + struct.pack("!d", float(obj))
    if t is str:
        b = obj.encode("utf-8")
        return b"S" + _uvarint(len(b)) + b
    if t is bytes or isinstance(obj, (bytearray, memoryview)):
        b = bytes(obj)
        return b"B" + _uvarint(len(b)) + b
    if is_dataclass(obj):
        obj = asdict(obj)
    if isinstance(obj, (list, tuple)):
        parts = bytearray(b"L" + _uvarint(len(obj)))
        for it in obj:
            parts += canonical_encode(it)
        return bytes(parts)
    if isinstance(obj, dict):
        items = [(canonical_encode(k), canonical_encode(v)) for k, v in obj.items()]
        items.sort(key=lambda kv: kv[0])
        parts = bytearray(b"M" + _uvarint(len(items)))
        for ek, ev in items:
            parts += ek + ev
        return bytes(parts)
    # stable fallback
    s = str(obj).encode("utf-8")
    return b"S" + _uvarint(len(s)) + s

# =========================
# Snapshot container format
# =========================
# Layout (all big-endian unless noted):
# [MAGIC=SNAP] [VER=u16=1] [FLAGS=u16] [TS_MS=u64] [TOC_COUNT=u32]
# Then TOC entries:
#   repeated TOC:
#     [NAME_LEN=u8][NAME bytes][CHUNK_COUNT=u32][UNCOMP_LEN=u32][COMP_LEN=u32][OFFSET=u64][HASH_U64=u64]
# Payload area:
#   For each section: sequence of chunks:
#     chunk: [CFLAG=u8 (0|1 compressed)] [RAW_LEN=u32] [COMP_LEN=u32] [CRC32=u32] [DATA...]
# Trailer:
# [GLOBAL_HASH_U64] [OPTIONAL_BLAKE2B_16 if FLAGS bit set]
#
# Notes:
# - Sections are independent (TOC contains their total sizes and offset into payload area).
# - Global hash covers header (except MAGIC/VER), TOC raw bytes, and all chunk data (raw after decompress).

MAGIC = b"SNAP"
VERSION = 1
FLAG_BLAKE2B = 1 << 0

@dataclass(slots=True)
class Section:
    name: str
    data: bytes  # uncompressed logical bytes

@dataclass(slots=True)
class Snapshot:
    ts_ms: int
    sections: List[Section]
    flags: int = 0
    global_hash_u64: int = 0
    blake2b_16: Optional[bytes] = None

# =========================
# Builder / Reader
# =========================

class SnapshotBuilder:
    def __init__(self, *, compress: bool = True, chunk_raw_size: int = 64 * 1024, mix_blake2b: bool = False) -> None:
        self.sections: List[Section] = []
        self.compress = compress
        self.chunk = max(4096, int(chunk_raw_size))
        self.flags = FLAG_BLAKE2B if mix_blake2b else 0

    def add_section(self, name: str, data: bytes) -> None:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("section data must be bytes-like")
        self.sections.append(Section(name=name, data=bytes(data)))

    def add_json_like(self, name: str, obj: Any) -> None:
        self.add_section(name, canonical_encode(obj))

    def build(self) -> bytes:
        # Prepare TOC entries (without offsets yet)
        toc_entries = []
        payload_blobs: List[bytes] = []
        offset = 0

        for sec in sorted(self.sections, key=lambda s: s.name):
            chunks = list(_chunk_it(sec.data, self.chunk))
            chunk_blobs: List[bytes] = []
            for raw in chunks:
                if self.compress:
                    comp = zlib.compress(raw, level=6)
                    use_comp = len(comp) < len(raw)
                else:
                    comp = raw
                    use_comp = False
                cflag = 1 if use_comp else 0
                body = comp if use_comp else raw
                crc = zlib.crc32(raw) & 0xFFFFFFFF
                header = struct.pack("!BIII", cflag, len(raw), len(body), crc)
                chunk_blobs.append(header + body)
            payload = b"".join(chunk_blobs)
            payload_blobs.append(payload)
            un_len = len(sec.data)
            comp_len = len(payload)
            hash_u64 = fnv1a64(sec.data)
            toc_entries.append([sec.name, len(chunks), un_len, comp_len, offset, hash_u64])
            offset += comp_len

        # Build header + TOC
        ts_ms = int(time.monotonic() * 1000)
        header = bytearray()
        header += MAGIC
        header += struct.pack("!HHQI", VERSION, self.flags, ts_ms, len(toc_entries))

        toc_bytes = bytearray()
        for name, ch_cnt, un_len, comp_len, off, h64 in toc_entries:
            nb = name.encode("utf-8")
            if len(nb) > 255:
                raise ValueError("section name too long")
            toc_bytes += struct.pack("!B", len(nb)) + nb
            toc_bytes += struct.pack("!IIIQQ", ch_cnt, un_len, comp_len, off, h64)

        payload_all = b"".join(payload_blobs)

        # Global hash covers: flags/ts/toc_count + toc_bytes + raw data of sections (not compressed)
        gh = fnv1a64(bytes(header[4:]))  # skip MAGIC
        gh = fnv1a64(toc_bytes, gh)
        for sec in sorted(self.sections, key=lambda s: s.name):
            gh = fnv1a64(sec.data, gh)

        trailer = bytearray()
        trailer += struct.pack("!Q", gh)
        if self.flags & FLAG_BLAKE2B:
            m = hashlib.blake2b(b"".join(sec.data for sec in sorted(self.sections, key=lambda s: s.name)), digest_size=16)
            trailer += m.digest()

        return bytes(header + toc_bytes + payload_all + trailer)

class SnapshotReader:
    def __init__(self, blob: bytes) -> None:
        self.blob = blob
        self._parse()

    def _parse(self) -> None:
        b = self.blob
        p = 0
        if b[p:p+4] != MAGIC:
            raise ValueError("invalid magic")
        p += 4
        ver, flags = struct.unpack("!HH", b[p:p+4]); p += 4
        if ver != VERSION:
            raise ValueError(f"unsupported version {ver}")
        self.flags = flags
        ts_ms, toc_count = struct.unpack("!QI", b[p:p+12]); p += 12
        self.ts_ms = ts_ms

        self.toc: List[Tuple[str, int, int, int, int, int]] = []
        for _ in range(toc_count):
            nlen = b[p]; p += 1
            name = b[p:p+nlen].decode("utf-8"); p += nlen
            ch_cnt, un_len, comp_len, offset, h64 = struct.unpack("!IIIQQ", b[p:p+28]); p += 28
            self.toc.append((name, ch_cnt, un_len, comp_len, offset, h64))

        self.payload_off = p
        # Trailer at end:
        self.global_hash_u64 = struct.unpack("!Q", b[-8:])[0]
        self.blake2b_16 = b[-24:-8] if (self.flags & FLAG_BLAKE2B) else None

        # Optional verification of CRCs deferred to read_section()

    def list_sections(self) -> List[str]:
        return [t[0] for t in self.toc]

    def read_section(self, name: str, verify_crc: bool = True) -> bytes:
        rec = next((t for t in self.toc if t[0] == name), None)
        if rec is None:
            raise KeyError(name)
        _, ch_cnt, un_len, comp_len, offset, h64 = rec
        p = self.payload_off + offset
        end = p + comp_len
        out = bytearray()
        for _ in range(ch_cnt):
            cflag, raw_len, comp_len, crc = struct.unpack("!BIII", self.blob[p:p+13])
            p += 13
            body = self.blob[p:p+comp_len]; p += comp_len
            raw = zlib.decompress(body) if cflag == 1 else body
            if len(raw) != raw_len:
                raise ValueError("chunk length mismatch")
            if verify_crc and (zlib.crc32(raw) & 0xFFFFFFFF) != crc:
                raise ValueError("chunk crc mismatch")
            out += raw
        if len(out) != un_len:
            raise ValueError("section total length mismatch")
        if fnv1a64(out) != h64:
            raise ValueError("section hash mismatch")
        return bytes(out)

# =========================
# Delta (patch) format per section
# =========================
# Simple instruction stream over bytes:
#  OP_COPY  (0x00) <len uvarint> <data bytes>
#  OP_XOR   (0x01) <len uvarint> <delta bytes>    # apply bytewise XOR to base slice of same length
#  OP_SKIP  (0x02) <len uvarint>                  # copy from base unchanged
# Stream applies sequentially over base to produce target.

OP_COPY = 0x00
OP_XOR  = 0x01
OP_SKIP = 0x02

def _emit_copy(buf: bytearray, data: bytes) -> None:
    buf += bytes([OP_COPY]) + _uvarint(len(data)) + data

def _emit_xor(buf: bytearray, delta: bytes) -> None:
    buf += bytes([OP_XOR]) + _uvarint(len(delta)) + delta

def _emit_skip(buf: bytearray, n: int) -> None:
    buf += bytes([OP_SKIP]) + _uvarint(n)

def _diff_bytes(a: bytes, b: bytes, block: int = 64) -> bytes:
    """
    Very compact and fast delta suitable for snapshots where sections change sparsely.
    Heuristic: scan blocks, emit SKIP for equal blocks, XOR for small diffs, COPY otherwise.
    """
    out = bytearray()
    i = 0
    la, lb = len(a), len(b)
    if la != lb:
        # length mismatch -> full COPY target
        _emit_copy(out, b)
        return bytes(out)

    while i < lb:
        run = min(block, lb - i)
        aa = a[i:i+run]
        bb = b[i:i+run]
        if aa == bb:
            _emit_skip(out, run)
        else:
            # check XOR sparsity
            x = bytes([aa[j] ^ bb[j] for j in range(run)])
            # XOR wins if more than half zeroes (sparse changes)
            zero = x.count(0)
            if zero >= run // 2:
                _emit_xor(out, x)
            else:
                _emit_copy(out, bb)
        i += run
    return bytes(out)

def _apply_patch_to_bytes(base: bytes, patch: bytes) -> bytes:
    out = bytearray()
    p = 0
    i = 0
    while p < len(patch):
        op = patch[p]; p += 1
        # read uvarint
        n = 0; shift = 0
        while True:
            b = patch[p]; p += 1
            n |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        if op == OP_SKIP:
            out += base[i:i+n]
            i += n
        elif op == OP_COPY:
            out += patch[p:p+n]; p += n
            i += n
        elif op == OP_XOR:
            delta = patch[p:p+n]; p += n
            blk = bytearray(base[i:i+n])
            for k in range(n):
                blk[k] ^= delta[k]
            out += blk
            i += n
        else:
            raise ValueError("bad patch op")
    if i != len(base):
        # If patch covered fewer bytes (should not), append tail from base
        out += base[i:]
    return bytes(out)

@dataclass(slots=True)
class Delta:
    base_hash_u64: int
    target_hash_u64: int
    sections: Dict[str, bytes]  # name -> patch bytes (or full COPY stream)
    ts_ms: int

def make_delta(base_blob: bytes, target_blob: bytes) -> bytes:
    """
    Build delta between two snapshot blobs. Returns bytes:
    [MAGD] [VER=u16=1] [TS=u64] [BASE_H=u64] [TGT_H=u64] [COUNT=u32]
      repeated:
        [NAME_LEN=u8][NAME][PATCH_LEN=u32][PATCH_BYTES...]
    """
    base = SnapshotReader(base_blob)
    tgt  = SnapshotReader(target_blob)
    # Build per-section union
    names = sorted(set(base.list_sections()) | set(tgt.list_sections()))
    patches: Dict[str, bytes] = {}

    for n in names:
        a = base.read_section(n) if n in base.list_sections() else b""
        b = tgt.read_section(n) if n in tgt.list_sections() else b""
        if a == b:
            # represent equality as SKIP of full length (or empty if both empty)
            if len(a) > 0:
                patches[n] = bytes([OP_SKIP]) + _uvarint(len(a))
            else:
                patches[n] = b""
        else:
            if len(a) == len(b) and len(a) > 0:
                patches[n] = _diff_bytes(a, b)
            else:
                buf = bytearray()
                _emit_copy(buf, b)
                patches[n] = bytes(buf)

    # Serialize delta
    out = bytearray()
    out += b"MAGD" + struct.pack("!HQQQI", VERSION, int(time.monotonic()*1000), base.global_hash_u64, tgt.global_hash_u64, len(patches))
    for n in sorted(patches.keys()):
        nb = n.encode("utf-8")
        pb = patches[n]
        out += struct.pack("!B", len(nb)) + nb + struct.pack("!I", len(pb)) + pb
    return bytes(out)

def apply_delta(base_blob: bytes, delta_blob: bytes) -> bytes:
    """
    Apply delta to base snapshot. Returns reconstructed target snapshot bytes.
    Verifies base hash if provided.
    """
    b = delta_blob
    if b[:4] != b"MAGD":
        raise ValueError("invalid delta magic")
    ver, ts_ms, base_h, tgt_h, cnt = struct.unpack("!HQQQI", b[4:4+26])
    if ver != VERSION:
        raise ValueError("delta version mismatch")
    p = 4 + 26
    patches: Dict[str, bytes] = {}
    for _ in range(cnt):
        nlen = b[p]; p += 1
        name = b[p:p+nlen].decode("utf-8"); p += nlen
        plen = struct.unpack("!I", b[p:p+4])[0]; p += 4
        patches[name] = b[p:p+plen]; p += plen

    base = SnapshotReader(base_blob)
    if base.global_hash_u64 != base_h:
        # We still can try applying but mark mismatch
        pass

    # Rebuild new sections
    names = sorted(set(base.list_sections()) | set(patches.keys()))
    builder = SnapshotBuilder(compress=True, chunk_raw_size=64*1024, mix_blake2b=bool(base.flags & FLAG_BLAKE2B))
    for n in names:
        a = base.read_section(n) if n in base.list_sections() else b""
        patch = patches.get(n, None)
        if patch is None or len(patch) == 0:
            data = a
        else:
            data = _apply_patch_to_bytes(a, patch)
        builder.add_section(n, data)
    out = builder.build()
    tgt = SnapshotReader(out)
    if tgt_h != 0 and tgt.global_hash_u64 != tgt_h:
        raise ValueError("target hash mismatch after applying delta")
    return out

# =========================
# Deterministic helpers for ECS-like worlds
# =========================

def encode_world_state(*, entities: Mapping[int, Mapping[str, Any]]) -> bytes:
    """
    Deterministically сериализует мир вида:
    entities = {
        entity_id: {
            "cmp_name": { ...component dict or dataclass... },
            ...
        }, ...
    }
    Упорядочивание: по entity_id возр., затем по имени компонента.
    """
    # Normalize dataclasses -> dicts; ensure primitives only
    norm: Dict[int, Dict[str, Any]] = {}
    for eid in sorted(int(k) for k in entities.keys()):
        comps = entities[eid]
        cdict: Dict[str, Any] = {}
        for cname in sorted(comps.keys()):
            cv = comps[cname]
            if is_dataclass(cv):
                cv = asdict(cv)
            cdict[cname] = cv
        norm[eid] = cdict
    return canonical_encode({"e": norm})

# =========================
# Snapshot store with budgets
# =========================

@dataclass(slots=True)
class StoreConfig:
    max_snapshots: int = 256
    max_bytes: int = 256 * 1024 * 1024
    max_age_ms: int = 10 * 60 * 1000  # 10 minutes

@dataclass(slots=True)
class Stored:
    tick: int
    blob: bytes
    ts_ms: int
    bytes: int

class SnapshotStore:
    """
    Simple in-memory store with pruning by count/bytes/age. Deterministic removal (oldest first).
    """
    def __init__(self, cfg: StoreConfig = StoreConfig()) -> None:
        self.cfg = cfg
        self._order: List[int] = []
        self._items: Dict[int, Stored] = {}
        self._acc_bytes = 0

    def put(self, tick: int, blob: bytes) -> None:
        t = int(tick)
        if t in self._items:
            self._acc_bytes -= self._items[t].bytes
        now = int(time.monotonic() * 1000)
        item = Stored(tick=t, blob=blob, ts_ms=now, bytes=len(blob))
        self._items[t] = item
        if t not in self._order:
            self._order.append(t)
            self._order.sort()
        self._acc_bytes += item.bytes
        self._prune(now)

    def get(self, tick: int) -> Optional[bytes]:
        it = self._items.get(int(tick))
        return it.blob if it else None

    def nearest_before(self, tick: int) -> Optional[bytes]:
        t = int(tick)
        cand = [k for k in self._order if k <= t]
        if not cand:
            return None
        return self._items[cand[-1]].blob

    def _prune(self, now_ms: int) -> None:
        # By age
        while self._order:
            t0 = self._order[0]
            if now_ms - self._items[t0].ts_ms <= self.cfg.max_age_ms:
                break
            self._acc_bytes -= self._items[t0].bytes
            self._items.pop(t0, None)
            self._order.pop(0)
        # By count
        while len(self._order) > self.cfg.max_snapshots:
            t0 = self._order.pop(0)
            self._acc_bytes -= self._items[t0].bytes
            self._items.pop(t0, None)
        # By bytes
        while self._acc_bytes > self.cfg.max_bytes and self._order:
            t0 = self._order.pop(0)
            self._acc_bytes -= self._items[t0].bytes
            self._items.pop(t0, None)

# =========================
# Utilities
# =========================

def _chunk_it(b: bytes, size: int) -> Iterable[bytes]:
    for i in range(0, len(b), size):
        yield b[i:i+size]

# =========================
# __all__
# =========================

__all__ = [
    "Snapshot",
    "SnapshotBuilder",
    "SnapshotReader",
    "Delta",
    "make_delta",
    "apply_delta",
    "encode_world_state",
    "SnapshotStore",
    "StoreConfig",
    "canonical_encode",
    "fnv1a64",
]
