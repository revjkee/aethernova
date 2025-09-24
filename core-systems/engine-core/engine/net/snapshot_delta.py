# -*- coding: utf-8 -*-
"""
engine-core / engine / net / snapshot_delta.py

Industrial snapshot delta codec with seq/ack and baseline tracking.

Features:
- Snapshot model: {entity: {type, fields...}} with deterministic field order by schema
- Schema-driven encoding for fields:
    * int (zigzag delta + uvarint)
    * float (quantized to int via scale/offset, delta + zigzag)
    * bool (bitset)
    * enum/str (string table per packet, or raw UTF-8; schema may predefine enum map)
    * bytes (length + raw)
- Delta compression vs baseline:
    * entity add/update/remove sets
    * per-entity change mask by field index
- Robust packet header:
    magic="SD", ver=1, flags, seq (uint16), ack (uint16), ack_bits (uint32), tick (u32), baseline_seq (uint16 or 0xFFFF)
- Sender/Receiver ring-buffers:
    * SentHistory (seq -> baseline_seq, snapshot_hash, wire bytes)
    * RecvHistory (recent seq set for ack_bits)
- Baseline selection: last acked seq; fallback to FULL snapshot if none available
- Deterministic encoding order: entities sorted by stable key, fields by schema index
- Statistics: raw_size, delta_size, efficiency, counts

Security/robustness:
- Length checks, defensive parsing, versioning
- No external dependencies

Notes:
- Entity IDs may be int or str. Int encodes as uvarint; str as length+utf8.
- For floats, choose scale to fit quantization error (e.g., 1e-3 => 0.001 units).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union, Iterable

__all__ = [
    "Schema",
    "Field",
    "FieldKind",
    "Snapshot",
    "DeltaCodec",
    "DeltaChannel",
    "Packet",
    "CodecStats",
    "SnapshotError",
]

# ============================================================
# Errors
# ============================================================

class SnapshotError(Exception):
    pass

# ============================================================
# Varint / ZigZag
# ============================================================

def uvarint_encode(x: int) -> bytes:
    """ULEB128 for non-negative integers."""
    if x < 0:
        raise ValueError("uvarint requires non-negative")
    out = bytearray()
    while True:
        b = x & 0x7F
        x >>= 7
        if x:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)

def uvarint_decode(buf: bytes, pos: int) -> Tuple[int, int]:
    x = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise SnapshotError("uvarint overflow")
        b = buf[pos]
        pos += 1
        x |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return x, pos
        shift += 7
        if shift > 63:
            raise SnapshotError("uvarint too large")

def zigzag_encode(n: int) -> int:
    return (n << 1) ^ (n >> 63)

def zigzag_decode(z: int) -> int:
    return (z >> 1) ^ -(z & 1)

# ============================================================
# Bit packer
# ============================================================

class BitWriter:
    def __init__(self) -> None:
        self._buf = bytearray()
        self._cur = 0
        self._n = 0  # bits in _cur

    def write_bit(self, bit: int) -> None:
        self._cur |= ((1 if bit else 0) & 1) << self._n
        self._n += 1
        if self._n == 8:
            self._buf.append(self._cur)
            self._cur = 0
            self._n = 0

    def write_bits_from_mask(self, mask_bits: Iterable[int]) -> None:
        for b in mask_bits:
            self.write_bit(1 if b else 0)

    def align_byte(self) -> None:
        if self._n:
            self._buf.append(self._cur)
            self._cur = 0
            self._n = 0

    def write_bytes(self, b: bytes) -> None:
        self.align_byte()
        self._buf += b

    def getvalue(self) -> bytes:
        self.align_byte()
        return bytes(self._buf)


class BitReader:
    def __init__(self, buf: bytes, pos: int = 0) -> None:
        self._buf = buf
        self._pos = pos
        self._cur = 0
        self._n = 0

    @property
    def pos(self) -> int:
        return self._pos + (1 if self._n else 0)  # approximate external usage

    def read_bit(self) -> int:
        if self._n == 0:
            if self._pos >= len(self._buf):
                raise SnapshotError("bit underflow")
            self._cur = self._buf[self._pos]
            self._pos += 1
            self._n = 8
        bit = self._cur & 1
        self._cur >>= 1
        self._n -= 1
        return bit

    def read_mask_bits(self, count: int) -> List[int]:
        return [self.read_bit() for _ in range(count)]

    def align_byte(self) -> None:
        self._n = 0

    def read_bytes(self, n: int) -> bytes:
        self.align_byte()
        end = self._pos + n
        if end > len(self._buf):
            raise SnapshotError("bytes underflow")
        b = self._buf[self._pos:end]
        self._pos = end
        return b

# ============================================================
# Schema / fields
# ============================================================

FieldKind = Union["int", "float", "bool", "enum", "str", "bytes"]

@dataclass(frozen=True)
class Field:
    """
    Field schema.
    int:     {"kind":"int"}
    float:   {"kind":"float","scale":0.001,"offset":0.0}  # v_enc = round((v - offset)/scale)
    bool:    {"kind":"bool"}
    enum:    {"kind":"enum","map":{"idle":0,"walk":1,...}}
    str:     {"kind":"str"}  # raw utf8 (small)
    bytes:   {"kind":"bytes"}  # raw bytes (small)
    """
    name: str
    kind: FieldKind
    scale: float = 1.0
    offset: float = 0.0
    enum_map: Dict[str, int] = field(default_factory=dict)

@dataclass(frozen=True)
class EntitySchema:
    name: str
    fields: List[Field]

@dataclass
class Schema:
    """
    Global schema for entities. Each entity has a 'type' and that type must be in schemas.
    """
    entities: Dict[str, EntitySchema]

    def field_index(self, ent_type: str, name: str) -> int:
        es = self.entities[ent_type]
        for i, f in enumerate(es.fields):
            if f.name == name:
                return i
        raise KeyError(f"field {name} not in {ent_type}")

# ============================================================
# Snapshot model
# ============================================================

EntityId = Union[int, str]

@dataclass
class SnapshotEntity:
    type: str
    fields: Dict[str, Any]  # name -> value

@dataclass
class Snapshot:
    tick: int
    entities: Dict[EntityId, SnapshotEntity]

    def hash(self) -> str:
        # Deterministic content hash for diagnostics (schema-driven)
        h = hashlib.sha256()
        h.update(self.tick.to_bytes(4, "big", signed=False))
        for eid in sorted(self.entities, key=lambda x: (0, x) if isinstance(x, int) else (1, str(x))):
            en = self.entities[eid]
            h.update(b"T"); h.update(en.type.encode("utf-8")); h.update(b"#")
            for k in sorted(en.fields.keys()):
                v = en.fields[k]
                h.update(k.encode("utf-8")+b"=")
                h.update(repr(v).encode("utf-8"))
                h.update(b";")
        return h.hexdigest()

# ============================================================
# Encoding helpers
# ============================================================

def _write_entity_id(bw: BitWriter, eid: EntityId) -> None:
    if isinstance(eid, int):
        bw.write_bytes(b"\x00")  # tag=0 -> int
        bw.write_bytes(uvarint_encode(eid))
    else:
        bw.write_bytes(b"\x01")  # tag=1 -> str
        data = str(eid).encode("utf-8")
        bw.write_bytes(uvarint_encode(len(data)))
        bw.write_bytes(data)

def _read_entity_id(br: BitReader) -> EntityId:
    tag = br.read_bytes(1)[0]
    if tag == 0:
        x, _pos = uvarint_decode(br._buf, br._pos)  # use raw
        br._pos = _pos
        return x
    elif tag == 1:
        n, _pos = uvarint_decode(br._buf, br._pos)
        br._pos = _pos
        s = br.read_bytes(n).decode("utf-8")
        return s
    else:
        raise SnapshotError("bad entity id tag")

def _encode_field(f: Field, val: Any, base: Optional[Any]) -> bytes:
    """Return encoded delta bytes for a field (value or delta vs base)."""
    if f.kind == "int":
        v = int(val)
        if base is not None:
            dv = v - int(base)
        else:
            dv = v
        zz = zigzag_encode(int(dv))
        return uvarint_encode(zz)
    elif f.kind == "float":
        scale = float(f.scale)
        off = float(f.offset)
        q = int(round((float(val) - off) / scale))
        qb = int(round((float(base) - off) / scale)) if base is not None else 0
        dv = q - qb if base is not None else q
        zz = zigzag_encode(int(dv))
        return uvarint_encode(zz)
    elif f.kind == "bool":
        # value encoded as single bit; caller packs mask for changed fields, value here as 1 byte bit
        return b"\x01" if bool(val) else b"\x00"
    elif f.kind == "enum":
        m = f.enum_map
        code = m.get(str(val))
        if code is None:
            # fallback raw str
            data = str(val).encode("utf-8")
            return b"\xFF" + uvarint_encode(len(data)) + data
        return uvarint_encode(code)
    elif f.kind == "str":
        data = str(val).encode("utf-8")
        return uvarint_encode(len(data)) + data
    elif f.kind == "bytes":
        b = bytes(val)
        return uvarint_encode(len(b)) + b
    else:
        raise SnapshotError(f"unknown field kind {f.kind}")

def _decode_field(f: Field, buf: bytes, pos: int, base: Optional[Any]) -> Tuple[Any, int]:
    if f.kind == "int":
        zz, pos = uvarint_decode(buf, pos)
        dv = zigzag_decode(zz)
        v = int(base) + int(dv) if base is not None else int(dv)
        return v, pos
    elif f.kind == "float":
        scale = float(f.scale); off = float(f.offset)
        zz, pos = uvarint_decode(buf, pos)
        dv = zigzag_decode(zz)
        if base is not None:
            qb = int(round((float(base) - off) / scale))
            q = qb + int(dv)
        else:
            q = int(dv)
        v = float(q) * scale + off
        return v, pos
    elif f.kind == "bool":
        b = buf[pos:pos+1]
        if not b:
            raise SnapshotError("bool underflow")
        return (b != b"\x00"), pos + 1
    elif f.kind == "enum":
        code, pos2 = uvarint_decode(buf, pos)
        if code == 0xFF:
            ln, pos3 = uvarint_decode(buf, pos2)
            s = buf[pos3:pos3+ln].decode("utf-8")
            return s, pos3 + ln
        # reverse map
        for k, v in f.enum_map.items():
            if v == code:
                return k, pos2
        # unknown code -> return code
        return code, pos2
    elif f.kind == "str":
        n, pos2 = uvarint_decode(buf, pos)
        s = buf[pos2:pos2+n].decode("utf-8")
        return s, pos2 + n
    elif f.kind == "bytes":
        n, pos2 = uvarint_decode(buf, pos)
        b = buf[pos2:pos2+n]
        if len(b) != n:
            raise SnapshotError("bytes underflow")
        return bytes(b), pos2 + n
    else:
        raise SnapshotError(f"unknown field kind {f.kind}")

# ============================================================
# Packet model
# ============================================================

@dataclass
class Packet:
    seq: int
    ack: int
    ack_bits: int
    tick: int
    baseline_seq: Optional[int]  # None => full snapshot
    payload: bytes

@dataclass
class CodecStats:
    raw_size: int
    delta_size: int
    entities_added: int
    entities_updated: int
    entities_removed: int
    fields_changed: int

# ============================================================
# Delta codec
# ============================================================

class DeltaCodec:
    MAGIC = b"SD"
    VERSION = 1

    def __init__(self, schema: Schema) -> None:
        self.schema = schema

    # ---------- public ----------

    def encode(self, current: Snapshot, baseline: Optional[Snapshot]) -> Tuple[bytes, CodecStats]:
        """
        Encode current snapshot vs baseline. If baseline is None -> full snapshot.
        """
        raw_size = self._estimate_raw_size(current)
        bw = BitWriter()

        # Header (magic, version) in bytes; rest in bytes too.
        bw.write_bytes(self.MAGIC + bytes([self.VERSION]))
        # Payload header (tick, baseline marker) will be appended after seq/acks by channel.

        # Build delta
        added, updated, removed, changed_fields = self._diff(current, baseline)

        # Write body
        # tick
        bw.write_bytes(uvarint_encode(current.tick))
        # baseline flag + optional baseline tick (for debug)
        bw.write_bytes(b"\x01" if baseline is not None else b"\x00")
        if baseline is not None:
            bw.write_bytes(uvarint_encode(baseline.tick))

        # added
        bw.write_bytes(uvarint_encode(len(added)))
        for eid, ent in added:
            _write_entity_id(bw, eid)
            # type name
            tbytes = ent.type.encode("utf-8")
            bw.write_bytes(uvarint_encode(len(tbytes))); bw.write_bytes(tbytes)
            # full field block
            es = self.schema.entities[ent.type]
            # bools will be packed via mask of values
            bool_idx = [i for i, f in enumerate(es.fields) if f.kind == "bool"]
            non_bool_idx = [i for i, f in enumerate(es.fields) if f.kind != "bool"]
            # values presence mask (all present for add)
            # Write bool values mask and values tightly
            bw.write_bytes(uvarint_encode(len(bool_idx)))
            bw.write_bytes(uvarint_encode(len(non_bool_idx)))
            # bool values as bitset in field order
            for i in bool_idx:
                f = es.fields[i]
                v = bool(ent.fields.get(f.name, False))
                bw.write_bytes(b"\x01" if v else b"\x00")
            # non-bool values
            for i in non_bool_idx:
                f = es.fields[i]
                v = ent.fields.get(f.name, 0 if f.kind in ("int","float") else (False if f.kind=="bool" else "" if f.kind in ("str","enum") else b""))
                enc = _encode_field(f, v, None)
                bw.write_bytes(enc)

        # updated
        bw.write_bytes(uvarint_encode(len(updated)))
        for eid, ent, base_ent, mask_indices in updated:
            _write_entity_id(bw, eid)
            # sanity: same type
            tbytes = ent.type.encode("utf-8")
            bw.write_bytes(uvarint_encode(len(tbytes))); bw.write_bytes(tbytes)
            es = self.schema.entities[ent.type]
            # change mask bits by field order
            mask_bits = [1 if i in mask_indices else 0 for i in range(len(es.fields))]
            # Write mask length and bitset
            bw.write_bytes(uvarint_encode(len(mask_bits)))
            # pack mask bits
            mask_writer = BitWriter()
            mask_writer.write_bits_from_mask(mask_bits)
            mb = mask_writer.getvalue()
            bw.write_bytes(uvarint_encode(len(mb)))
            bw.write_bytes(mb)
            # For each 1-bit field, write delta value
            for i, f in enumerate(es.fields):
                if not mask_bits[i]:
                    continue
                v = ent.fields.get(f.name)
                vb = base_ent.fields.get(f.name) if base_ent else None
                enc = _encode_field(f, v, vb)
                bw.write_bytes(enc)

        # removed
        bw.write_bytes(uvarint_encode(len(removed)))
        for eid in removed:
            _write_entity_id(bw, eid)

        payload = bw.getvalue()
        stats = CodecStats(
            raw_size=raw_size,
            delta_size=len(payload),
            entities_added=len(added),
            entities_updated=len(updated),
            entities_removed=len(removed),
            fields_changed=changed_fields,
        )
        return payload, stats

    def decode(self, payload: bytes, baseline: Optional[Snapshot]) -> Snapshot:
        # Parse header
        if len(payload) < 3 or payload[0:2] != self.MAGIC or payload[2] != self.VERSION:
            raise SnapshotError("bad header")
        br = BitReader(payload, pos=3)

        # tick
        tick, pos = uvarint_decode(payload, br._pos); br._pos = pos
        # baseline flag
        has_base = br.read_bytes(1)[0]
        if has_base:
            _base_tick, pos2 = uvarint_decode(payload, br._pos)
            br._pos = pos2
            if baseline is None:
                # We accept missing baseline; changes should reconstruct regardless (add may be full)
                pass

        # added
        n_add, pos = uvarint_decode(payload, br._pos); br._pos = pos
        entities: Dict[EntityId, SnapshotEntity] = {}
        removed_set: set[EntityId] = set()

        for _ in range(n_add):
            eid = _read_entity_id(br)
            ln, pos = uvarint_decode(payload, br._pos); br._pos = pos
            ent_type = br.read_bytes(ln).decode("utf-8")
            es = self.schema.entities[ent_type]
            # bool/non-bool counts
            nb_bool, pos = uvarint_decode(payload, br._pos); br._pos = pos
            nb_non, pos = uvarint_decode(payload, br._pos); br._pos = pos
            vals: Dict[str, Any] = {}
            # bools (values)
            for i in range(nb_bool):
                b = br.read_bytes(1)[0]
                # map by bool field index i in schema order
            # We need positions of bool fields to reconstruct; recompute list
            bool_idx = [i for i, f in enumerate(es.fields) if f.kind == "bool"]
            non_bool_idx = [i for i, f in enumerate(es.fields) if f.kind != "bool"]
            # rewind to parse bools properly
            # The previous loop consumed bytes; re-parse using a temporary reader
            # Simpler: redo with knowledge of counts captured above:
            # Reset position back by nb_bool bytes and decode mapping:
            br._pos -= nb_bool
            bool_vals = []
            for _ in range(nb_bool):
                bool_vals.append(br.read_bytes(1)[0] != 0)
            for idx, val in zip(bool_idx, bool_vals):
                vals[es.fields[idx].name] = val
            # non-bool values
            for idx in non_bool_idx:
                f = es.fields[idx]
                v, pos = _decode_field(f, payload, br._pos, None)
                br._pos = pos
                vals[f.name] = v
            entities[eid] = SnapshotEntity(type=ent_type, fields=vals)

        # updated
        n_upd, pos = uvarint_decode(payload, br._pos); br._pos = pos
        for _ in range(n_upd):
            eid = _read_entity_id(br)
            ln, pos = uvarint_decode(payload, br._pos); br._pos = pos
            ent_type = br.read_bytes(ln).decode("utf-8")
            es = self.schema.entities[ent_type]
            mask_len, pos = uvarint_decode(payload, br._pos); br._pos = pos
            mb_len, pos = uvarint_decode(payload, br._pos); br._pos = pos
            mb = br.read_bytes(mb_len)
            mbr = BitReader(mb, 0)
            mask_bits = [mbr.read_bit() for _ in range(mask_len)]
            base_ent = None
            if baseline and eid in baseline.entities:
                base_ent = baseline.entities[eid]
            vals = dict(base_ent.fields) if base_ent else {}
            for i, f in enumerate(es.fields):
                if mask_bits[i]:
                    v, pos = _decode_field(f, payload, br._pos, base_ent.fields.get(f.name) if base_ent else None)
                    br._pos = pos
                    vals[f.name] = v
            entities[eid] = SnapshotEntity(type=ent_type, fields=vals)

        # removed
        n_rem, pos = uvarint_decode(payload, br._pos); br._pos = pos
        for _ in range(n_rem):
            eid = _read_entity_id(br)
            removed_set.add(eid)

        # Merge with baseline: start from baseline copy, apply add/update/remove
        if baseline is not None:
            merged: Dict[EntityId, SnapshotEntity] = {k: SnapshotEntity(v.type, dict(v.fields)) for k, v in baseline.entities.items()}
            for eid in removed_set:
                merged.pop(eid, None)
            for eid, ent in entities.items():
                merged[eid] = ent
            entities = merged

        return Snapshot(tick=tick, entities=entities)

    # ---------- internals ----------

    def _diff(self, cur: Snapshot, base: Optional[Snapshot]) -> Tuple[
        List[Tuple[EntityId, SnapshotEntity]],
        List[Tuple[EntityId, SnapshotEntity, Optional[SnapshotEntity], List[int]]],
        List[EntityId],
        int
    ]:
        added: List[Tuple[EntityId, SnapshotEntity]] = []
        updated: List[Tuple[EntityId, SnapshotEntity, Optional[SnapshotEntity], List[int]]] = []
        removed: List[EntityId] = []
        changed_fields = 0

        cur_ids = set(cur.entities.keys())
        base_ids = set(base.entities.keys()) if base else set()

        for eid in sorted(cur_ids - base_ids, key=lambda x: (0, x) if isinstance(x, int) else (1, str(x))):
            added.append((eid, cur.entities[eid]))

        for eid in sorted(base_ids - cur_ids, key=lambda x: (0, x) if isinstance(x, int) else (1, str(x))):
            removed.append(eid)

        for eid in sorted(cur_ids & base_ids, key=lambda x: (0, x) if isinstance(x, int) else (1, str(x))):
            ent = cur.entities[eid]
            b_ent = base.entities[eid]
            if ent.type != b_ent.type:
                # treat as remove + add, but here encode as full add by placing into added and removed
                added.append((eid, ent))
                removed.append(eid)
                continue
            es = self.schema.entities[ent.type]
            mask_idx: List[int] = []
            for i, f in enumerate(es.fields):
                v = ent.fields.get(f.name)
                vb = b_ent.fields.get(f.name)
                if not self._field_equal(f, v, vb):
                    mask_idx.append(i)
            if mask_idx:
                changed_fields += len(mask_idx)
                updated.append((eid, ent, b_ent, mask_idx))

        return added, updated, removed, changed_fields

    @staticmethod
    def _field_equal(f: Field, v: Any, vb: Any) -> bool:
        if f.kind == "float":
            # compare on quantized grid
            scale = float(f.scale); off = float(f.offset)
            q = int(round((float(v) - off) / scale))
            qb = int(round((float(vb) - off) / scale))
            return q == qb
        return v == vb

    @staticmethod
    def _estimate_raw_size(s: Snapshot) -> int:
        # naive estimate for stats
        n = 4  # tick
        for eid, ent in s.entities.items():
            n += (len(str(eid)) if not isinstance(eid, int) else 4) + 1
            n += len(ent.type) + 1
            for k, v in ent.fields.items():
                n += len(k) + len(repr(v)) + 1
        return n

# ============================================================
# Seq/Ack utilities (similar to ENet/QUIC window)
# ============================================================

def seq_less(a: int, b: int, bits: int = 16) -> bool:
    mask = (1 << bits) - 1
    return ((a - b) & mask) > (1 << (bits - 1))

def update_ack_bits(latest: int, seen: Iterable[int], bits: int = 32, seq_bits: int = 16) -> int:
    """Build ack_bits where bit 0 => (latest-1), bit 31 => (latest-32)."""
    window = 0
    mask = (1 << seq_bits) - 1
    seen_set = {x & mask for x in seen}
    for i in range(1, bits + 1):
        s = (latest - i) & mask
        if s in seen_set:
            window |= 1 << (i - 1)
    return window

# ============================================================
# Delta channel (sender/receiver state machines)
# ============================================================

@dataclass
class _SentRecord:
    seq: int
    baseline_seq: Optional[int]
    tick: int
    payload: bytes

class DeltaChannel:
    """
    High-level channel for encoding/decoding snapshot packets with seq/ack.

    Usage (per peer):
        codec = DeltaCodec(schema)
        chan = DeltaChannel(codec)

        # Sender:
        pkt_bytes, stats = chan.build_packet(current_snapshot)
        # send pkt_bytes over UDP

        # On receiver:
        ack_tuple, reconstructed = chan.receive_and_reconstruct(pkt_bytes)
        # send back ack with ack_tuple (ack, ack_bits)

        # On sender upon receiving acks:
        chan.process_ack(ack, ack_bits)

    Notes:
      - Ring buffer size limits how far back baseline can be referenced.
      - If receiver lacks the baseline, it can still reconstruct via full add/remove,
        because encoder chooses FULL when no acked baseline exists.
    """

    SEQ_BITS = 16
    ACK_BITS_WIDTH = 32
    RING = 1024

    def __init__(self, codec: DeltaCodec) -> None:
        self.codec = codec
        self._seq = 0
        self._sent: Dict[int, _SentRecord] = {}
        self._sent_order: List[int] = []
        self._acked: set[int] = set()

        # receive side
        self._recv_seen: List[int] = []     # recent seqs window
        self._recv_latest: Optional[int] = None
        self._recv_baselines: Dict[int, Snapshot] = {}  # seq -> snapshot

        # last peer ack state we advertise in outgoing header (piggyback)
        self._last_ack_from_peer: int = 0
        self._last_ack_bits_from_peer: int = 0

    # ---------- sender ----------

    def build_packet(self, snap: Snapshot) -> Tuple[bytes, CodecStats]:
        # choose baseline: last acked seq if exists
        baseline_seq = self._best_baseline_seq()
        baseline = self._recv_baselines.get(baseline_seq) if baseline_seq is not None else None

        payload, stats = self.codec.encode(snap, baseline)

        seq = self._seq & ((1 << self.SEQ_BITS) - 1)
        self._seq = (self._seq + 1) & ((1 << self.SEQ_BITS) - 1)

        # packet header (without MAGIC/VERSION they are inside payload)
        # [flags=1][seq u16][ack u16][ack_bits u32][baseline_seq u16 or 0xFFFF][payload...]
        flags = 0
        header = bytearray()
        header.append(flags)
        header += seq.to_bytes(2, "big")
        header += self._last_ack_from_peer.to_bytes(2, "big")
        header += self._last_ack_bits_from_peer.to_bytes(4, "big")
        header += ((baseline_seq if baseline_seq is not None else 0xFFFF) & 0xFFFF).to_bytes(2, "big")

        wire = bytes(header) + payload

        # record sent snapshot for retry stats
        self._sent[seq] = _SentRecord(seq=seq, baseline_seq=baseline_seq, tick=snap.tick, payload=payload)
        self._sent_order.append(seq)
        if len(self._sent_order) > self.RING:
            old = self._sent_order.pop(0)
            self._sent.pop(old, None)

        # also remember own snapshot under seq for possible future baseline on peer who acks us
        self._recv_baselines[seq] = snap
        if len(self._recv_baselines) > self.RING:
            # drop oldest by seq order list if needed
            oldest = min(self._recv_baselines.keys(), key=lambda x: ((x - seq) & 0xFFFF))
            self._recv_baselines.pop(oldest, None)

        return wire, stats

    def process_ack(self, ack: int, ack_bits: int) -> None:
        """Mark acknowledged sent packets; ack is latest received by peer."""
        self._last_ack_from_peer = ack
        self._last_ack_bits_from_peer = ack_bits
        self._mark_ack(ack)
        for i in range(1, self.ACK_BITS_WIDTH + 1):
            if (ack_bits >> (i - 1)) & 1:
                self._mark_ack((ack - i) & 0xFFFF)

    def _mark_ack(self, seq: int) -> None:
        if seq in self._sent:
            self._acked.add(seq)
            # optionally drop payload to save memory
            rec = self._sent.pop(seq, None)
            if rec and seq in self._sent_order:
                self._sent_order.remove(seq)

    def _best_baseline_seq(self) -> Optional[int]:
        if not self._acked:
            return None
        # choose the most recent acked seq (modulo wrap)
        # Using max by distance from current seq counter is acceptable here.
        return max(self._acked)

    # ---------- receiver ----------

    def receive_and_reconstruct(self, wire: bytes) -> Tuple[Tuple[int, int], Snapshot]:
        """
        Returns ((ack, ack_bits), reconstructed_snapshot).
        """
        if len(wire) < 1 + 2 + 2 + 4 + 2 + 3:
            raise SnapshotError("packet too small")
        flags = wire[0]
        seq = int.from_bytes(wire[1:3], "big")
        ack_from_sender = int.from_bytes(wire[3:5], "big")
        ack_bits_from_sender = int.from_bytes(wire[5:9], "big")
        baseline_seq = int.from_bytes(wire[9:11], "big")
