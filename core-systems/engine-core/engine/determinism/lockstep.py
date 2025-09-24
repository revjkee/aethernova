# engine-core/engine/determinism/lockstep.py
"""
Industrial-grade lockstep verification for deterministic simulations.

Key features:
- Lockstep tick coordination (peer set, per-tick input aggregation)
- Canonical, language-agnostic serialization (type-tagged + varint) for inputs/state
- 64-bit FNV-1a digest per tick (stable across platforms) + optional BLAKE2b
- Deterministic RNG (PCG32), per-session and per-tick derivation
- History ring buffer with (inputs, digest, acks), divergence detection
- Snapshot registry + rollback window + guided re-simulation hooks
- ACK mask (last K ticks) to help fast convergence and packet loss resilience
- Transport-agnostic: you bring networking; module returns opaque packets/ACKs
- No external dependencies; pure Python 3.10+

Typical flow:
  1) Create LockstepCoordinator with session_seed and peer IDs.
  2) submit_input(peer, tick, input_obj) for all peers per tick.
  3) when all inputs ready -> aggregate_inputs(tick) -> apply to your simulation.
  4) finalize_tick(tick, world_state_obj) -> returns digest.
  5) Exchange digest packets between peers; call apply_remote_digest(peer, tick, digest, ack_mask).
  6) On mismatch -> earliest_divergence() and (optionally) rollback_and_resimulate(...).

This module does NOT run the simulation; it only verifies determinism and coordinates inputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple
import struct
import time

# =========================
# Utilities: varint + canonical encoding
# =========================

def _uvarint_encode(n: int) -> bytes:
    """Unsigned varint (protobuf-style)."""
    if n < 0:
        raise ValueError("uvarint requires non-negative")
    out = bytearray()
    while True:
        to_write = n & 0x7F
        n >>= 7
        if n:
            out.append(to_write | 0x80)
        else:
            out.append(to_write)
            break
    return bytes(out)

def _encode_value(v: Any) -> bytes:
    """
    Canonical type-tagged encoding:
      N=null, T=true, F=false,
      I<int-as-decimal>; D<double IEEE-754 big-endian),
      S<len,varint><utf8>, B<len,varint><bytes>,
      L<len,varint><items...>, M<len,varint><k,v ...> with keys sorted by encoded bytes.
    Deterministic across platforms.
    """
    t = type(v)
    if v is None:
        return b"N"
    if t is bool:
        return b"T" if v else b"F"
    if t is int:
        # decimal ASCII with terminator; avoids ambiguity and endianness issues
        b = str(v).encode("ascii")
        return b"I" + _uvarint_encode(len(b)) + b
    if t is float:
        # IEEE-754 double, network byte order
        return b"D" + struct.pack("!d", float(v))
    if t is str:
        b = v.encode("utf-8")
        return b"S" + _uvarint_encode(len(b)) + b
    if t is bytes or isinstance(v, (bytearray, memoryview)):
        b = bytes(v)
        return b"B" + _uvarint_encode(len(b)) + b
    if isinstance(v, (list, tuple)):
        parts = bytearray(b"L" + _uvarint_encode(len(v)))
        for item in v:
            parts += _encode_value(item)
        return bytes(parts)
    if isinstance(v, dict):
        # keys encoded & sorted lexicographically by their encoded representation
        enc_items = [(_encode_value(k), _encode_value(v2)) for k, v2 in v.items()]
        enc_items.sort(key=lambda kv: kv[0])
        parts = bytearray(b"M" + _uvarint_encode(len(enc_items)))
        for ek, ev in enc_items:
            parts += ek + ev
        return bytes(parts)
    # Fallback: string representation (stable for simple objects)
    s = str(v).encode("utf-8")
    return b"S" + _uvarint_encode(len(s)) + s

# =========================
# 64-bit FNV-1a hashing (stable, fast)
# =========================

FNV64_OFFSET = 0xcbf29ce484222325
FNV64_PRIME  = 0x100000001b3

def fnv1a64(data: bytes, seed: int = FNV64_OFFSET) -> int:
    """64-bit FNV-1a; returns unsigned 64-bit int."""
    h = seed & 0xFFFFFFFFFFFFFFFF
    # Process in chunks for speed
    for b in data:
        h ^= b
        h = (h * FNV64_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h

def _hex_u64(x: int) -> str:
    return f"{x & 0xFFFFFFFFFFFFFFFF:016x}"

# =========================
# Deterministic RNG: PCG32
# =========================

class PCG32:
    """Minimal PCG32 (xorshift; LCG) deterministic RNG with 32-bit outputs."""
    __slots__ = ("_state", "_inc")

    def __init__(self, seed: int, seq: int = 0x853c49e6748fea9b) -> None:
        self._state = 0
        self._inc = ((seq << 1) | 1) & 0xFFFFFFFFFFFFFFFF
        self._advance(seed + 0x9e3779b97f4a7c15)

    def _advance(self, delta: int) -> None:
        # LCG: state = state * mul + inc
        self._state = (self._state * 6364136223846793005 + self._inc + (delta & 0xFFFFFFFFFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF

    def random_u32(self) -> int:
        old = self._state
        self._advance(0)
        xorshifted = (((old >> 18) ^ old) >> 27) & 0xFFFFFFFF
        rot = (old >> 59) & 0x1F
        return ((xorshifted >> rot) | (xorshifted << ((-rot) & 31))) & 0xFFFFFFFF

    def random(self) -> float:
        # [0,1)
        return (self.random_u32() >> 8) / float(1 << 24)

    def randint(self, lo: int, hi: int) -> int:
        if hi < lo:
            lo, hi = hi, lo
        span = hi - lo + 1
        return lo + (self.random_u32() % span)

# =========================
# Config & data structures
# =========================

@dataclass(slots=True)
class LockstepConfig:
    tick_rate: int = 60
    max_peers: int = 64
    history_ticks: int = 4096                 # ring size for (inputs,digests)
    ack_window: int = 64                      # bits in ack mask
    allow_future_inputs: bool = True          # allow submit for future ticks
    digest_include_state: bool = True         # mix in world_state snapshot bytes
    digest_include_inputs: bool = True        # mix in canonical aggregated inputs
    reseed_rng_every_tick: bool = True        # derive RNG from session_seed^tick
    input_timeout_ms: int = 0                 # 0 = wait indefinitely (coordinator-wise)
    # Optional stronger digest (slower). If True, blake2b-128 over canonical bytes is mixed into FNV.
    mix_blake2b: bool = False


@dataclass(slots=True)
class TickInputs:
    tick: int
    # peer_id -> canonical bytes of input for this tick
    inputs: Dict[int, bytes] = field(default_factory=dict)

@dataclass(slots=True)
class TickRecord:
    tick: int
    digest_u64: int
    ack_mask: int
    agg_inputs_hash: int
    state_hash: int

@dataclass(slots=True)
class PeerDigest:
    latest_tick: int
    digest_u64: int
    ack_mask: int

# =========================
# Lockstep Coordinator
# =========================

class LockstepCoordinator:
    """
    Coordinates lockstep inputs and digests, verifies equality across peers,
    tracks history and supports rollback window.

    Integration points:
      - provide your list of peer_ids (ints)
      - call submit_input(peer_id, tick, obj) for each tick
      - when inputs_ready(tick) -> aggregate_inputs(tick) for your simulation step
      - after sim step -> finalize_tick(tick, world_state_obj) -> digest (hex)
      - exchange PeerDigest packets via your networking; on receive -> apply_remote_digest(...)
      - on mismatch -> earliest_divergence() and use snapshots/rollback as needed
    """

    def __init__(self, peer_ids: Iterable[int], session_seed: int, config: LockstepConfig | None = None) -> None:
        self.cfg = config or LockstepConfig()
        self.session_seed = int(session_seed) & 0xFFFFFFFFFFFFFFFF
        peers = list(sorted(set(int(p) for p in peer_ids)))
        if len(peers) == 0:
            raise ValueError("LockstepCoordinator requires at least one peer (self is also a peer)")
        if len(peers) > self.cfg.max_peers:
            raise ValueError("too many peers")
        self.peers: List[int] = peers

        self._inputs: Dict[int, TickInputs] = {}     # tick -> TickInputs
        self._history: Dict[int, TickRecord] = {}    # tick -> record
        self._history_order: List[int] = []          # ring indices
        self._peer_latest: Dict[int, PeerDigest] = {}  # peer_id -> their latest digest/ack

        # Snapshot ring: tick -> bytes (opaque)
        self._snapshots: Dict[int, bytes] = {}

        # Divergence tracking
        self._divergent_ticks: Dict[int, List[int]] = {}  # tick -> [peer_ids that disagree]

        # Time bookkeeping for optional input timeout
        self._submit_ts: Dict[Tuple[int, int], float] = {}  # (tick, peer_id) -> time.monotonic()

    # ---------- Input handling ----------

    def submit_input(self, peer_id: int, tick: int, input_obj: Any) -> None:
        """Submit input for peer at tick. Accepts any JSON-like/bytes; encoded canonically."""
        pid = int(peer_id)
        if pid not in self.peers:
            raise KeyError(f"peer {pid} not registered")
        if tick < 0:
            raise ValueError("tick must be >= 0")
        if not self.cfg.allow_future_inputs and tick > self.current_tick_hint():
            raise ValueError("future inputs not allowed by config")

        entry = self._inputs.get(tick)
        if entry is None:
            entry = self._inputs.setdefault(tick, TickInputs(tick=tick))
        entry.inputs[pid] = _encode_value(input_obj)
        self._submit_ts[(tick, pid)] = time.monotonic()

    def inputs_ready(self, tick: int) -> bool:
        """True when all peers have submitted input for tick or timeout expired."""
        entry = self._inputs.get(tick)
        if entry is None:
            return False
        if len(entry.inputs) >= len(self.peers):
            return True
        if self.cfg.input_timeout_ms <= 0:
            return False
        # Check timeout: if at least one input exists and the oldest is older than timeout, treat as ready (missing -> default empty)
        oldest = min((self._submit_ts.get((tick, p), float("inf")) for p in entry.inputs.keys()), default=float("inf"))
        if oldest is float("inf"):
            return False
        return (time.monotonic() - oldest) * 1000.0 >= self.cfg.input_timeout_ms

    def aggregate_inputs(self, tick: int) -> List[Tuple[int, bytes]]:
        """
        Returns a list of (peer_id, input_bytes) sorted by peer_id.
        Missing peers (if timeout) receive empty input b"N" (encoded None).
        """
        entry = self._inputs.get(tick)
        if entry is None:
            raise KeyError(f"no inputs for tick {tick}")
        result: List[Tuple[int, bytes]] = []
        for pid in self.peers:
            b = entry.inputs.get(pid, _encode_value(None))
            result.append((pid, b))
        result.sort(key=lambda kv: kv[0])
        return result

    # ---------- Digest computation ----------

    def _hash_agg_inputs(self, tick: int) -> int:
        """Stable hash for aggregated inputs at tick."""
        parts = bytearray()
        parts += b"T" + _uvarint_encode(tick)
        for pid, data in self.aggregate_inputs(tick):
            parts += b"P" + _uvarint_encode(pid) + b"V" + _uvarint_encode(len(data)) + data
        return fnv1a64(bytes(parts))

    def _hash_state_bytes(self, state_obj: Any) -> int:
        b = _encode_value(state_obj)
        return fnv1a64(b)

    def _derive_rng(self, tick: int) -> PCG32:
        seed = self.session_seed ^ (tick & 0xFFFFFFFFFFFFFFFF)
        return PCG32(seed=seed, seq=(seed ^ 0xda3e39cb94b95bdb))

    def finalize_tick(self, tick: int, world_state_obj: Any) -> str:
        """
        Called after you applied inputs(tick) to your deterministic simulation.
        Returns hex digest for network. Stores TickRecord in history ring.
        """
        if tick not in self._inputs:
            # Allow finalize even if no inputs were submitted (e.g., empty frame)
            self._inputs[tick] = TickInputs(tick=tick)

        agg_h = self._hash_agg_inputs(tick) if self.cfg.digest_include_inputs else 0
        st_h  = self._hash_state_bytes(world_state_obj) if self.cfg.digest_include_state else 0

        # Mix tick, session_seed, RNG sample for extra diffusion
        rng = self._derive_rng(tick) if self.cfg.reseed_rng_every_tick else PCG32(self.session_seed)
        mix = 0
        for _ in range(2):
            mix = fnv1a64(struct.pack("!Q", rng.random_u32() | (rng.random_u32() << 32)), seed=mix or FNV64_OFFSET)

        h = FNV64_OFFSET
        for piece in (
            struct.pack("!Q", tick & 0xFFFFFFFFFFFFFFFF),
            struct.pack("!Q", self.session_seed),
            struct.pack("!Q", agg_h),
            struct.pack("!Q", st_h),
            struct.pack("!Q", mix),
        ):
            h = fnv1a64(piece, seed=h)

        # Optional BLAKE2b-128 mix (stdlib, but off by default to remain pure FNV)
        if self.cfg.mix_blake2b:
            import hashlib
            m = hashlib.blake2b(_encode_value(world_state_obj), digest_size=16)
            h = fnv1a64(m.digest(), seed=h)

        ack = self._make_ack_mask_local()
        rec = TickRecord(tick=tick, digest_u64=h, ack_mask=ack, agg_inputs_hash=agg_h, state_hash=st_h)
        self._put_history(rec)
        return _hex_u64(h)

    # ---------- ACK & history ----------

    def _put_history(self, rec: TickRecord) -> None:
        self._history[rec.tick] = rec
        self._history_order.append(rec.tick)
        # Keep ring size bounded
        while len(self._history_order) > self.cfg.history_ticks:
            drop = self._history_order.pop(0)
            self._history.pop(drop, None)
            self._inputs.pop(drop, None)
            self._snapshots.pop(drop, None)
            self._divergent_ticks.pop(drop, None)

    def _make_ack_mask_local(self) -> int:
        """Ack mask over our own recent ticks: bit 0 is latest-1, bit k is latest-(k+1)."""
        if not self._history_order:
            return 0
        latest = self._history_order[-1]
        mask = 0
        for i in range(1, self.cfg.ack_window + 1):
            t = latest - i
            if t in self._history:
                mask |= (1 << (i - 1))
        return mask

    def build_peer_packet(self) -> PeerDigest:
        """Returns our latest digest + ack mask for sending to peers."""
        if not self._history_order:
            return PeerDigest(latest_tick=-1, digest_u64=0, ack_mask=0)
        t = self._history_order[-1]
        rec = self._history[t]
        return PeerDigest(latest_tick=t, digest_u64=rec.digest_u64, ack_mask=rec.ack_mask)

    # ---------- Remote digest handling ----------

    def apply_remote_digest(self, peer_id: int, tick: int, digest_hex: str, ack_mask: int) -> None:
        """Apply a remote peer's reported digest & ACK mask. Detect divergence."""
        pid = int(peer_id)
        if pid not in self.peers:
            raise KeyError("unknown peer")
        try:
            remote_u64 = int(digest_hex, 16) & 0xFFFFFFFFFFFFFFFF
        except Exception as e:
            raise ValueError("invalid digest hex") from e

        self._peer_latest[pid] = PeerDigest(latest_tick=tick, digest_u64=remote_u64, ack_mask=int(ack_mask))

        # Compare if we have this tick
        rec = self._history.get(tick)
        if rec is None:
            return
        if rec.digest_u64 != remote_u64:
            self._divergent_ticks.setdefault(tick, []).append(pid)

    def earliest_divergence(self) -> Optional[int]:
        """Returns the smallest tick where any peer disagrees with us."""
        return min(self._divergent_ticks.keys()) if self._divergent_ticks else None

    def clear_divergence_from(self, tick: int) -> None:
        """Clear divergence markers from tick and later (e.g., after rollback)."""
        for t in list(self._divergent_ticks.keys()):
            if t >= tick:
                self._divergent_ticks.pop(t, None)

    # ---------- Snapshot / rollback ----------

    def register_snapshot(self, tick: int, snapshot_bytes: bytes) -> None:
        """Register opaque snapshot bytes for a tick (produced by your simulation)."""
        if not isinstance(snapshot_bytes, (bytes, bytearray, memoryview)):
            raise TypeError("snapshot must be bytes-like")
        self._snapshots[int(tick)] = bytes(snapshot_bytes)
        # keep snapshots within history window
        while len(self._snapshots) > self.cfg.history_ticks:
            old = min(self._snapshots.keys())
            self._snapshots.pop(old, None)

    def get_snapshot(self, tick: int) -> Optional[bytes]:
        return self._snapshots.get(int(tick))

    def rollback_and_resimulate(
        self,
        from_tick: int,
        to_tick_inclusive: int,
        *,
        apply_inputs_fn: Callable[[int, List[Tuple[int, bytes]], Optional[bytes]], bytes],
    ) -> List[Tuple[int, str]]:
        """
        Re-simulate from snapshot at 'from_tick' up to 'to_tick_inclusive' (inclusive).
        The callback must:
          - take (tick, aggregated_inputs_sorted, snapshot_bytes_or_None_for_first_call)
          - apply inputs deterministically and return new world_state snapshot (bytes) after the tick
        Returns list of (tick, hex_digest) for the re-simulated range and updates history in-place.
        """
        start_snap = self.get_snapshot(from_tick)
        if start_snap is None:
            raise KeyError(f"no snapshot for tick {from_tick}")

        digests: List[Tuple[int, str]] = []
        snap = start_snap

        for t in range(from_tick, to_tick_inclusive + 1):
            ag = self.aggregate_inputs(t)
            snap = apply_inputs_fn(t, ag, snap if t == from_tick else None)
            # Recompute digest using the same finalize logic but without dropping history outside ring
            agg_h = self._hash_agg_inputs(t) if self.cfg.digest_include_inputs else 0
            st_h  = self._hash_state_bytes(snap) if self.cfg.digest_include_state else 0
            rng = self._derive_rng(t) if self.cfg.reseed_rng_every_tick else PCG32(self.session_seed)
            mix = 0
            for _ in range(2):
                mix = fnv1a64(struct.pack("!Q", rng.random_u32() | (rng.random_u32() << 32)), seed=mix or FNV64_OFFSET)
            h = FNV64_OFFSET
            for piece in (
                struct.pack("!Q", t & 0xFFFFFFFFFFFFFFFF),
                struct.pack("!Q", self.session_seed),
                struct.pack("!Q", agg_h),
                struct.pack("!Q", st_h),
                struct.pack("!Q", mix),
            ):
                h = fnv1a64(piece, seed=h)

            rec = TickRecord(tick=t, digest_u64=h, ack_mask=self._make_ack_mask_local(), agg_inputs_hash=agg_h, state_hash=st_h)
            self._put_history(rec)
            self.register_snapshot(t, snap)
            digests.append((t, _hex_u64(h)))

        # After successful re-sim: clear divergence marks in this window
        self.clear_divergence_from(from_tick)
        return digests

    # ---------- Introspection / helpers ----------

    def current_tick_hint(self) -> int:
        """Best-effort current tick (latest finalized + 1 or min input tick)."""
        if self._history_order:
            return self._history_order[-1] + 1
        if self._inputs:
            return min(self._inputs.keys())
        return 0

    def get_record(self, tick: int) -> Optional[TickRecord]:
        return self._history.get(int(tick))

    def required_peers_missing(self, tick: int) -> List[int]:
        """Peers that have not submitted input for tick."""
        entry = self._inputs.get(tick)
        if entry is None:
            return list(self.peers)
        return [p for p in self.peers if p not in entry.inputs]

    # ---------- Convenience: encode/decode packets ----------

    def make_digest_packet(self, tick: int) -> Dict[str, Any]:
        """Serializable packet with our digest for given tick (use after finalize_tick)."""
        rec = self._history.get(tick)
        if rec is None:
            raise KeyError(f"no record for tick {tick}")
        return {
            "tick": tick,
            "digest": _hex_u64(rec.digest_u64),
            "ack": rec.ack_mask,
        }

    def accept_digest_packet(self, peer_id: int, packet: Mapping[str, Any]) -> None:
        """Accept a remote packet in form produced by make_digest_packet/build_peer_packet."""
        self.apply_remote_digest(peer_id, int(packet["tick"]), str(packet["digest"]), int(packet["ack"]))


# =========================
# __all__
# =========================

__all__ = [
    # config & types
    "LockstepConfig",
    "TickInputs",
    "TickRecord",
    "PeerDigest",
    # rng
    "PCG32",
    # hashing
    "fnv1a64",
    # coordinator
    "LockstepCoordinator",
]
