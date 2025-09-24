# engine-core/engine/ingest/player_input.py
"""
Industrial-grade player input ingestion for deterministic lockstep engines.

Features:
- Unified schema for input packets and per-tick samples (keyboard/mouse/gamepad)
- Deterministic canonical serialization + 64-bit FNV-1a digest for verification
- Reorder-safe jitter buffer with seq/tick dedupe, late/early drop windows
- Deadzone/normalization/quantization for axes; clamp & validation
- Debounce + press/hold/double-tap edge detection with stable thresholds
- Rate limits (RPS) and spam guards per player
- Merge multiple device sources; last-writer-wins with timestamps
- Missing-tick prediction (hold-to-repeat, axis hold), bounded horizon
- Emits per-tick InputSnapshot for lockstep application
- No external deps

This module is transport-agnostic. Upstream code feeds InputPacket objects as they arrive.
Downstream lockstep consumes InputSnapshot via InputIngestor.pop_ready_snapshots().
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, IntFlag, auto
from typing import Dict, List, Optional, Tuple, Iterable, Deque
import collections
import math
import time

# =========================
# Deterministic hashing & canonical encoding (shared philosophy with determinism/lockstep.py)
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

def canonical_encode(obj) -> bytes:
    """
    Compact, deterministic, type-tagged encoding:
      N,T,F,I(len)+ascii,D(8 bytes BE),S(len)+utf8,
      L(len)+items, M(len)+sorted(k,v) by encoded k
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
        import struct
        return b"D" + struct.pack("!d", float(obj))
    if t is str:
        b = obj.encode("utf-8")
        return b"S" + _uvarint(len(b)) + b
    if t is bytes or isinstance(obj, (bytearray, memoryview)):
        b = bytes(obj)
        return b"B" + _uvarint(len(b)) + b
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
    # fallback: stringify deterministically
    s = str(obj).encode("utf-8")
    return b"S" + _uvarint(len(s)) + s

# =========================
# Types
# =========================

class DeviceType(IntEnum):
    KEYBOARD_MOUSE = 1
    GAMEPAD = 2
    TOUCH = 3

class Buttons(IntFlag):
    NONE = 0
    FIRE = 1 << 0
    JUMP = 1 << 1
    DASH = 1 << 2
    RELOAD = 1 << 3
    ABILITY1 = 1 << 4
    ABILITY2 = 1 << 5
    INTERACT = 1 << 6
    SPRINT = 1 << 7
    CROUCH = 1 << 8

@dataclass(slots=True)
class Axes:
    # normalized in [-1,1], quantized to qstep
    move_x: float = 0.0
    move_y: float = 0.0
    aim_x: float = 0.0
    aim_y: float = 0.0
    trigger_l: float = 0.0
    trigger_r: float = 0.0

    def as_tuple(self) -> Tuple[float, float, float, float, float, float]:
        return (self.move_x, self.move_y, self.aim_x, self.aim_y, self.trigger_l, self.trigger_r)

@dataclass(slots=True)
class InputPacket:
    """
    Raw packet as received from client.
    - seq: strictly increasing per-connection sequence
    - tick: client simulation tick (optional but recommended)
    - dt_ms: client frame time used for tap/hold detection on client-side; server uses its own thresholds
    - device: device type
    - axes: normalized axes
    - buttons: bitmask
    - flags: reserved for client hints (e.g., aim assist)
    - client_send_ts_ms: client monotonic ms (optional)
    - server_recv_ts_ms: filled by receiver on arrival
    """
    player_id: int
    seq: int
    tick: Optional[int]
    dt_ms: int
    device: DeviceType
    axes: Axes
    buttons: Buttons
    flags: int = 0
    client_send_ts_ms: Optional[int] = None
    server_recv_ts_ms: Optional[int] = None

    def to_dict(self) -> Dict:
        return {
            "player": self.player_id,
            "seq": self.seq,
            "tick": self.tick,
            "dt": self.dt_ms,
            "dev": int(self.device),
            "axes": list(self.axes.as_tuple()),
            "btn": int(self.buttons),
            "flags": int(self.flags),
            "cs": self.client_send_ts_ms,
            "sr": self.server_recv_ts_ms,
        }

    def digest_u64(self) -> int:
        return fnv1a64(canonical_encode(self.to_dict()))

@dataclass(slots=True)
class InputSnapshot:
    """
    Per-tick merged, cleaned and quantized input ready for lockstep.
    """
    player_id: int
    tick: int
    axes_q: Tuple[int, int, int, int, int, int]     # quantized int16
    buttons: Buttons
    edges_pressed: Buttons                          # rising edges in this tick
    edges_released: Buttons                         # falling edges in this tick
    tap_mask: Buttons                               # taps detected in this tick
    hold_mask: Buttons                              # holds (>= hold_ms)
    double_tap_mask: Buttons                        # double-taps
    source_seq_max: int                             # last contributing seq
    hash_u64: int                                   # digest for verification

# =========================
# Config
# =========================

@dataclass(slots=True)
class Deadzones:
    move: float = 0.15
    aim: float = 0.10
    trigger: float = 0.05

@dataclass(slots=True)
class Quantization:
    # int range [-qmax, qmax]
    qmax: int = 32767

@dataclass(slots=True)
class TapHoldConfig:
    tap_ms: int = 180
    double_tap_ms: int = 300
    hold_ms: int = 280

@dataclass(slots=True)
class JitterConfig:
    # reorder/dup windows in packets and ticks
    max_reorder: int = 64            # by seq
    max_future_ticks: int = 6        # accept packet with tick <= current+N
    max_past_ticks: int = 30         # ignore too old
    prediction_horizon: int = 3      # generate up to N missing tick snapshots

@dataclass(slots=True)
class RateLimits:
    max_packets_per_sec: int = 120
    burst: int = 240

@dataclass(slots=True)
class IngestConfig:
    deadzones: Deadzones = field(default_factory=Deadzones)
    quant: Quantization = field(default_factory=Quantization)
    tap_hold: TapHoldConfig = field(default_factory=TapHoldConfig)
    jitter: JitterConfig = field(default_factory=JitterConfig)
    rate: RateLimits = field(default_factory=RateLimits)
    axis_quant_step: float = 1.0 / 32767.0
    clamp_axes: bool = True

# =========================
# Helpers
# =========================

def _apply_deadzone(v: float, dz: float) -> float:
    if abs(v) <= dz:
        return 0.0
    # rescale outside deadzone to full range
    s = (abs(v) - dz) / (1.0 - dz)
    return math.copysign(s, v)

def _clamp01(x: float) -> float:
    return -1.0 if x < -1.0 else (1.0 if x > 1.0 else x)

def _quantize(x: float, qmax: int) -> int:
    return int(round(_clamp01(x) * qmax))

def _btns(new: Buttons, old: Buttons) -> Tuple[Buttons, Buttons]:
    pressed = Buttons((int(new) ^ int(old)) & int(new))
    released = Buttons((int(new) ^ int(old)) & int(old))
    return pressed, released

# =========================
# Token bucket for RPS
# =========================

class TokenBucket:
    def __init__(self, rate: float, burst: float) -> None:
        self.rate = float(max(0.0, rate))
        self.burst = float(max(1.0, burst))
        self.tokens = self.burst
        self.last = time.monotonic()

    def allow(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        dt = now - self.last
        if dt > 0:
            self.tokens = min(self.burst, self.tokens + dt * self.rate)
            self.last = now
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False

# =========================
# Core Ingestor
# =========================

@dataclass(slots=True)
class _PerPlayerState:
    last_seq: int = -1
    last_tick: Optional[int] = None
    last_buttons: Buttons = Buttons.NONE
    last_press_ts_ms: Dict[int, int] = field(default_factory=dict)
    last_release_ts_ms: Dict[int, int] = field(default_factory=dict)
    last_tap_ts_ms: Dict[int, int] = field(default_factory=dict)
    last_snapshot: Optional[InputSnapshot] = None

class InputIngestor:
    """
    Accepts InputPacket stream for a single player, produces per-tick InputSnapshot.
    Reorder-safe, deterministic, lockstep-ready.
    """

    def __init__(self, player_id: int, cfg: IngestConfig = IngestConfig()) -> None:
        self.player_id = int(player_id)
        self.cfg = cfg
        self._state = _PerPlayerState()
        self._queue: Deque[InputPacket] = collections.deque()
        self._rps = TokenBucket(rate=cfg.rate.max_packets_per_sec, burst=cfg.rate.burst)

    # ---- Public API ----

    def push_packet(self, pkt: InputPacket) -> bool:
        """
        Accept packet (returns False if dropped by validation/rate).
        Enforces seq monotonicity window, tick sanity, RPS.
        server_recv_ts_ms is filled if absent.
        """
        if not self._rps.allow(1.0):
            return False

        if pkt.player_id != self.player_id:
            return False

        if pkt.server_recv_ts_ms is None:
            pkt.server_recv_ts_ms = int(time.monotonic() * 1000)

        # seq window: accept if seq > last_seq - max_reorder
        if self._state.last_seq >= 0 and pkt.seq <= self._state.last_seq - self.cfg.jitter.max_reorder:
            return False

        # clamp axes and apply deadzones
        pkt.axes = self._sanitize_axes(pkt.axes)

        # enqueue and keep queue bounded
        self._queue.append(pkt)
        while len(self._queue) > 4096:
            self._queue.popleft()
        return True

    def pop_ready_snapshots(self, current_tick: int) -> List[InputSnapshot]:
        """
        Produce InputSnapshot(s) for ticks <= current_tick.
        Applies reorder/dedupe, fills missing ticks via prediction.
        Deterministic order.
        """
        ready: List[InputSnapshot] = []

        # 1) Move acceptable packets from queue into map by tick (latest by seq wins)
        by_tick: Dict[int, InputPacket] = {}
        while self._queue:
            pkt = self._queue[0]
            # Discard too old by tick
            if pkt.tick is not None and self._state.last_tick is not None and pkt.tick < self._state.last_tick - self.cfg.jitter.max_past_ticks:
                self._queue.popleft()
                continue

            # Only process those up to current_tick + max_future
            future_limit = current_tick + self.cfg.jitter.max_future_ticks
            if pkt.tick is not None and pkt.tick > future_limit:
                break  # keep in queue

            self._queue.popleft()

            # dedupe by tick -> choose packet with higher seq
            if pkt.tick is None:
                # if client didn't send tick, map to last_tick or current_tick
                t = self._state.last_tick + 1 if self._state.last_tick is not None else current_tick
                pkt.tick = t
            t = pkt.tick
            prev = by_tick.get(t)
            if prev is None or pkt.seq >= prev.seq:
                by_tick[t] = pkt

        # 2) Iterate ticks from last_tick+1 to min(current_tick, max(by_tick))
        start_tick = (self._state.last_tick + 1) if self._state.last_tick is not None else (min(by_tick.keys()) if by_tick else current_tick)
        end_tick = min(current_tick, max(by_tick.keys()) if by_tick else current_tick)

        # Bound prediction horizon
        if self._state.last_tick is not None:
            gap = (end_tick - self._state.last_tick)
            if gap > self.cfg.jitter.prediction_horizon:
                end_tick = self._state.last_tick + self.cfg.jitter.prediction_horizon

        t = start_tick
        while t <= end_tick:
            pkt = by_tick.get(t)

            if pkt is None:
                # Predict from last snapshot: hold buttons/axes
                snap = self._predict_snapshot(t)
            else:
                snap = self._build_snapshot_from_packet(pkt)

            ready.append(snap)
            self._state.last_tick = t
            t += 1

        return ready

    # ---- Internals ----

    def _sanitize_axes(self, a: Axes) -> Axes:
        dz = self.cfg.deadzones
        # clamp
        if self.cfg.clamp_axes:
            a = Axes(
                move_x=_clamp01(a.move_x), move_y=_clamp01(a.move_y),
                aim_x=_clamp01(a.aim_x), aim_y=_clamp01(a.aim_y),
                trigger_l=_clamp01(a.trigger_l), trigger_r=_clamp01(a.trigger_r),
            )
        # apply deadzones
        ax = Axes(
            move_x=_apply_deadzone(a.move_x, dz.move),
            move_y=_apply_deadzone(a.move_y, dz.move),
            aim_x=_apply_deadzone(a.aim_x, dz.aim),
            aim_y=_apply_deadzone(a.aim_y, dz.aim),
            trigger_l=_apply_deadzone(a.trigger_l, dz.trigger),
            trigger_r=_apply_deadzone(a.trigger_r, dz.trigger),
        )
        return ax

    def _quant_axes(self, a: Axes) -> Tuple[int, int, int, int, int, int]:
        q = self.cfg.quant.qmax
        return (
            _quantize(a.move_x, q),
            _quantize(a.move_y, q),
            _quantize(a.aim_x, q),
            _quantize(a.aim_y, q),
            _quantize(a.trigger_l, q),
            _quantize(a.trigger_r, q),
        )

    def _build_snapshot_from_packet(self, pkt: InputPacket) -> InputSnapshot:
        # update seq watermark
        self._state.last_seq = max(self._state.last_seq, pkt.seq)

        # edges & press/hold/tap with server time
        pressed, released = _btns(pkt.buttons, self._state.last_buttons)
        self._state.last_buttons = pkt.buttons

        now_ms = pkt.server_recv_ts_ms or int(time.monotonic() * 1000)

        tap_mask = Buttons.NONE
        hold_mask = Buttons.NONE
        double_mask = Buttons.NONE

        for bit in Buttons:
            if bit == Buttons.NONE:
                continue
            b = int(bit)
            if Buttons(b) in Buttons and (int(pressed) & b):
                self._state.last_press_ts_ms[b] = now_ms
                # double-tap detection
                last_tap = self._state.last_tap_ts_ms.get(b)
                if last_tap is not None and (now_ms - last_tap) <= self.cfg.tap_hold.double_tap_ms:
                    double_mask |= Buttons(b)
            if Buttons(b) in Buttons and (int(released) & b):
                self._state.last_release_ts_ms[b] = now_ms
                # tap if short press
                t0 = self._state.last_press_ts_ms.get(b)
                if t0 is not None and (now_ms - t0) <= self.cfg.tap_hold.tap_ms:
                    tap_mask |= Buttons(b)
                    self._state.last_tap_ts_ms[b] = now_ms
                # hold if long
                if t0 is not None and (now_ms - t0) >= self.cfg.tap_hold.hold_ms:
                    hold_mask |= Buttons(b)

        # quantify axes
        axes_q = self._quant_axes(pkt.axes)
        snap = InputSnapshot(
            player_id=self.player_id,
            tick=int(pkt.tick if pkt.tick is not None else (self._state.last_tick or 0)),
            axes_q=axes_q,
            buttons=pkt.buttons,
            edges_pressed=pressed,
            edges_released=released,
            tap_mask=tap_mask,
            hold_mask=hold_mask,
            double_tap_mask=double_mask,
            source_seq_max=self._state.last_seq,
            hash_u64=0,
        )
        snap.hash_u64 = self._snapshot_hash(snap)
        self._state.last_snapshot = snap
        return snap

    def _predict_snapshot(self, tick: int) -> InputSnapshot:
        # if no history, emit neutral
        if not self._state.last_snapshot:
            neutral_axes = (0, 0, 0, 0, 0, 0)
            snap = InputSnapshot(
                player_id=self.player_id,
                tick=int(tick),
                axes_q=neutral_axes,
                buttons=Buttons.NONE,
                edges_pressed=Buttons.NONE,
                edges_released=Buttons.NONE,
                tap_mask=Buttons.NONE,
                hold_mask=Buttons.NONE,
                double_tap_mask=Buttons.NONE,
                source_seq_max=self._state.last_seq,
                hash_u64=0,
            )
            snap.hash_u64 = self._snapshot_hash(snap)
            self._state.last_snapshot = snap
            return snap

        prev = self._state.last_snapshot
        # hold previous state; edges/taps only on real packets
        snap = InputSnapshot(
            player_id=self.player_id,
            tick=int(tick),
            axes_q=prev.axes_q,
            buttons=prev.buttons,
            edges_pressed=Buttons.NONE,
            edges_released=Buttons.NONE,
            tap_mask=Buttons.NONE,
            hold_mask=Buttons.NONE,
            double_tap_mask=Buttons.NONE,
            source_seq_max=self._state.last_seq,
            hash_u64=0,
        )
        snap.hash_u64 = self._snapshot_hash(snap)
        self._state.last_snapshot = snap
        return snap

    def _snapshot_hash(self, s: InputSnapshot) -> int:
        payload = {
            "p": s.player_id,
            "t": s.tick,
            "a": list(s.axes_q),
            "b": int(s.buttons),
            "ep": int(s.edges_pressed),
            "er": int(s.edges_released),
            "tm": int(s.tap_mask),
            "hm": int(s.hold_mask),
            "dm": int(s.double_tap_mask),
            "sq": s.source_seq_max,
        }
        return fnv1a64(canonical_encode(payload))

# =========================
# Convenience
# =========================

def merge_sources(packets: Iterable[InputPacket]) -> List[InputPacket]:
    """
    Merge multiple device streams into one, last-writer-wins by server_recv_ts_ms then seq.
    """
    arr = list(packets)
    arr.sort(key=lambda p: (p.server_recv_ts_ms or 0, p.seq))
    return arr

# =========================
# __all__
# =========================

__all__ = [
    "DeviceType",
    "Buttons",
    "Axes",
    "InputPacket",
    "InputSnapshot",
    "IngestConfig",
    "InputIngestor",
    "merge_sources",
    "fnv1a64",
    "canonical_encode",
]
