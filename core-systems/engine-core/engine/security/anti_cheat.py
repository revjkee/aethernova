# engine-core/engine/security/anti_cheat.py
"""
Industrial-grade Anti-Cheat module (server-side heuristics, integrity, evidence).

Design goals:
- Transport-agnostic: feed per-tick player samples and raw packets
- Integrity: HMAC-SHA256 over canonical-encoded envelope + rolling nonce + timestamp window
- Movement validation: max speed, acceleration, teleport, time dilation
- Command-rate: CPS/RPS anomalies, burstiness, input duplication
- Weapon rate: fire/reload cadence, recoil pattern drift (optional counters only)
- Aim heuristics: angular velocity, jerk, micro-jitter spectrum proxy (human/robot split)
- Lag switch signals: burst arrivals after gaps, input age distribution
- Scoring: per-category EWMA risk, strike/sanction ladder with decay and cool-down
- Evidence log: tamper-evident hash chain with canonical encoding; exportable snapshots
- Privacy: no PII, only gameplay telemetry hashes and minimal fields

No external dependencies. Python 3.10+.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict, is_dataclass
from typing import Any, Dict, List, Optional, Tuple, Mapping
import math
import time
import hmac
import hashlib
import struct
import collections

# =========================
# Canonical encoding + FNV
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

def canonical_encode(obj: Any) -> bytes:
    """
    Deterministic, compact encoding:
      N,T,F,I(len)+ascii,D(8 bytes BE),S(len)+utf8,B(len)+bytes,
      L(len)+items,M(len)+sorted(k,v)
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
    s = str(obj).encode("utf-8")
    return b"S" + _uvarint(len(s)) + s

# =========================
# Config
# =========================

@dataclass(slots=True)
class IntegrityConfig:
    # Allowed clock skew between client->server (ms)
    max_skew_ms: int = 1500
    # Allowed age of packet since client_send_ts (ms)
    max_age_ms: int = 2500
    # Nonce window (accept if nonce > last_nonce and within gap)
    max_nonce_gap: int = 1024

@dataclass(slots=True)
class MovementConfig:
    max_speed: float = 12.0          # units/sec
    max_accel: float = 50.0          # units/sec^2
    teleport_dist: float = 8.0       # hard jump threshold per tick
    dt_s: float = 1.0 / 60.0         # server tick
    time_dilation_tol: float = 0.20  # +/-20% of dt allowed before suspicion

@dataclass(slots=True)
class CommandConfig:
    max_commands_per_sec: int = 120
    max_burst: int = 40
    dup_window: int = 8              # identical successive samples window

@dataclass(slots=True)
class WeaponConfig:
    # Per-weapon allowed fire rate; map by weapon_id -> shots per second
    fire_rate_hz: Mapping[int, float] = field(default_factory=lambda: {1: 10.0, 2: 6.0})
    min_reload_s: Mapping[int, float] = field(default_factory=lambda: {1: 1.2, 2: 2.4})
    recoil_min_variance: float = 0.0005  # too-stable vertical/horizontal deltas

@dataclass(slots=True)
class AimConfig:
    max_angular_speed_deg_s: float = 900.0      # extreme flicks
    max_angular_jerk_deg_s2: float = 25000.0    # change of angular speed / s
    micro_jitter_floor: float = 0.0008          # too-perfect steadiness (no microsway)

@dataclass(slots=True)
class ScoringConfig:
    ewma_alpha: float = 0.15
    strike_thresholds: Mapping[str, float] = field(default_factory=lambda: {
        "integrity": 0.8, "movement": 1.0, "command": 1.0, "weapon": 1.0, "aim": 1.0, "lag": 1.0
    })
    # Action ladder based on total_risk
    actions: List[Tuple[float, str]] = field(default_factory=lambda: [
        (0.5, "WARN"),
        (1.0, "SHADOW_MITIGATE"),  # например, скрытая деградация хитскана
        (2.0, "KICK"),
        (3.0, "TEMP_BAN_24H"),
        (5.0, "PERMA_BAN"),
    ])
    decay_per_s: float = 0.02  # passive decay for total risk

@dataclass(slots=True)
class AntiCheatConfig:
    integrity: IntegrityConfig = field(default_factory=IntegrityConfig)
    movement: MovementConfig = field(default_factory=MovementConfig)
    command: CommandConfig = field(default_factory=CommandConfig)
    weapon: WeaponConfig = field(default_factory=WeaponConfig)
    aim: AimConfig = field(default_factory=AimConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)

# =========================
# Types
# =========================

@dataclass(slots=True)
class PacketEnvelope:
    player_id: int
    seq: int
    nonce: int
    client_send_ts_ms: int
    payload: bytes           # raw gameplay payload (already validated shape upstream)
    hmac_hex: str            # lowercase hex

@dataclass(slots=True)
class TickSample:
    """Per-tick interpreted snapshot for anti-cheat."""
    tick: int
    server_recv_ts_ms: int
    pos: Tuple[float, float, float]
    vel: Tuple[float, float, float]
    yaw_deg: float          # horizontal aim
    pitch_deg: float        # vertical aim
    cmd_fire: bool
    cmd_reload: bool
    weapon_id: int

# =========================
# Evidence log (hash chain)
# =========================

@dataclass(slots=True)
class EvidenceEntry:
    ts_ms: int
    tick: int
    category: str
    score: float
    details: Dict[str, Any]
    prev_hash_u64: int
    hash_u64: int

class EvidenceLog:
    def __init__(self, max_entries: int = 4096) -> None:
        self._max = max_entries
        self._entries: List[EvidenceEntry] = []
        self._last_hash = FNV64_OFFSET

    def _encode_entry(self, tick: int, category: str, score: float, details: Dict[str, Any]) -> bytes:
        obj = {"t": tick, "c": category, "s": round(score, 6), "d": details}
        return canonical_encode(obj)

    def add(self, tick: int, category: str, score: float, details: Dict[str, Any]) -> EvidenceEntry:
        ts = int(time.monotonic() * 1000)
        payload = self._encode_entry(tick, category, score, details)
        h = fnv1a64(payload, seed=self._last_hash)
        entry = EvidenceEntry(ts, tick, category, score, details, self._last_hash, h)
        self._entries.append(entry)
        self._last_hash = h
        while len(self._entries) > self._max:
            self._entries.pop(0)
        return entry

    def chain_tip(self) -> int:
        return self._last_hash

    def export(self) -> List[Dict[str, Any]]:
        return [asdict(e) for e in self._entries]

# =========================
# Core state per player
# =========================

@dataclass(slots=True)
class PlayerState:
    secret_key: bytes
    last_nonce: int = -1
    last_seq: int = -1
    last_tick: Optional[int] = None
    # movement state
    last_pos: Optional[Tuple[float, float, float]] = None
    last_vel: Optional[Tuple[float, float, float]] = None
    # aim dynamics
    last_yaw: Optional[float] = None
    last_pitch: Optional[float] = None
    last_ang_speed: float = 0.0
    # weapon cadence
    last_fire_ts_ms: Optional[int] = None
    last_reload_ts_ms: Optional[int] = None
    # command stats
    cmds_window: collections.deque = field(default_factory=lambda: collections.deque(maxlen=120))
    dup_counter: int = 0
    # risk (EWMA per category)
    risk: Dict[str, float] = field(default_factory=lambda: {k: 0.0 for k in ["integrity","movement","command","weapon","aim","lag"]})
    # totals
    total_risk: float = 0.0
    last_risk_ts: float = field(default_factory=time.monotonic)
    # evidence
    evidence: EvidenceLog = field(default_factory=lambda: EvidenceLog())

# =========================
# AntiCheat engine
# =========================

class AntiCheat:
    def __init__(self, cfg: AntiCheatConfig = AntiCheatConfig()) -> None:
        self.cfg = cfg
        self.players: Dict[int, PlayerState] = {}

    # ---- Player lifecycle ----

    def register_player(self, player_id: int, shared_secret: bytes) -> None:
        self.players[player_id] = PlayerState(secret_key=bytes(shared_secret))

    def unregister_player(self, player_id: int) -> None:
        self.players.pop(player_id, None)

    # ---- Integrity ----

    def verify_packet(self, env: PacketEnvelope) -> Tuple[bool, Optional[str]]:
        st = self.players.get(env.player_id)
        if not st:
            return False, "unknown_player"
        # HMAC
        mac = hmac.new(st.secret_key, canonical_encode({
            "p": env.player_id,
            "s": env.seq,
            "n": env.nonce,
            "t": env.client_send_ts_ms,
            "b": env.payload,
        }), hashlib.sha256).hexdigest()
        if mac != env.hmac_hex:
            self._raise_risk(env.player_id, "integrity", 1.0, env.seq, {"reason":"hmac_mismatch"})
            return False, "hmac_mismatch"

        # Nonce monotonicity with gap
        if st.last_nonce >= 0 and env.nonce <= st.last_nonce:
            self._raise_risk(env.player_id, "integrity", 0.6, env.seq, {"reason":"nonce_replay","nonce":env.nonce,"last":st.last_nonce})
            return False, "nonce_replay"
        if st.last_nonce >= 0 and env.nonce > st.last_nonce + self.cfg.integrity.max_nonce_gap:
            self._raise_risk(env.player_id, "integrity", 0.3, env.seq, {"reason":"nonce_jump","nonce":env.nonce,"last":st.last_nonce})

        # Time window
        now_ms = int(time.monotonic() * 1000)
        if abs(env.client_send_ts_ms - now_ms) > self.cfg.integrity.max_skew_ms:
            self._raise_risk(env.player_id, "integrity", 0.2, env.seq, {"reason":"clock_skew"})
        if now_ms - env.client_send_ts_ms > self.cfg.integrity.max_age_ms:
            self._raise_risk(env.player_id, "integrity", 0.4, env.seq, {"reason":"stale_packet","age_ms":now_ms-env.client_send_ts_ms})

        st.last_nonce = env.nonce
        st.last_seq = max(st.last_seq, env.seq)
        return True, None

    # ---- Tick processing ----

    def process_tick(self, player_id: int, sample: TickSample) -> Optional[str]:
        """
        Process interpreted per-tick sample; returns action if any should be applied now.
        """
        st = self.players.get(player_id)
        if not st:
            return None

        # Decay total risk
        self._decay_total(st)

        # Movement checks
        self._check_movement(player_id, st, sample)

        # Commands & duplicates
        self._check_commands(player_id, st, sample)

        # Weapon cadence
        self._check_weapon(player_id, st, sample)

        # Aim heuristics
        self._check_aim(player_id, st, sample)

        # Lag switch signals (age distribution inferred via server_recv_ts_ms deltas)
        self._check_lag(player_id, st, sample)

        st.last_tick = sample.tick
        return self._escalate(player_id, st)

    # ---- Checkers ----

    def _check_movement(self, pid: int, st: PlayerState, s: TickSample) -> None:
        cfg = self.cfg.movement
        dt = cfg.dt_s
        if st.last_pos is not None:
            dx = tuple(s.pos[i] - st.last_pos[i] for i in range(3))
            dist = math.sqrt(sum(d*d for d in dx))
            speed = dist / dt
            if speed > cfg.max_speed * (1.0 + cfg.time_dilation_tol):
                self._raise_risk(pid, "movement", min(1.0, (speed/cfg.max_speed)-1.0), s.tick, {"speed":round(speed,3), "max":cfg.max_speed})
            if dist > cfg.teleport_dist:
                self._raise_risk(pid, "movement", 0.9, s.tick, {"teleport_dist":round(dist,3)})
        if st.last_vel is not None and s.vel is not None:
            dv = tuple(s.vel[i] - st.last_vel[i] for i in range(3))
            accel = math.sqrt(sum(d*d for d in dv)) / dt
            if accel > cfg.max_accel:
                self._raise_risk(pid, "movement", min(1.0, (accel/cfg.max_accel)-1.0), s.tick, {"accel":round(accel,3),"max":cfg.max_accel})

        st.last_pos = s.pos
        st.last_vel = s.vel

    def _check_commands(self, pid: int, st: PlayerState, s: TickSample) -> None:
        cfg = self.cfg.command
        # push 1 per tick to window for CPS
        st.cmds_window.append(1)
        cps = sum(st.cmds_window) / max(1.0, (len(st.cmds_window) * self.cfg.movement.dt_s))
        if cps > cfg.max_commands_per_sec * 1.1:
            self._raise_risk(pid, "command", min(1.0, (cps/cfg.max_commands_per_sec)-1.0), s.tick, {"cps":round(cps,2)})

        # duplicate detection: if identical snapshots keep coming (basic proxy: same pos/aim within epsilon and no buttons)
        eps = 1e-6
        if st.last_pos and abs(s.yaw_deg - (st.last_yaw or s.yaw_deg)) < 1e-4 and abs(s.pitch_deg - (st.last_pitch or s.pitch_deg)) < 1e-4:
            # stationary + no fire/reload
            if (not s.cmd_fire) and (not s.cmd_reload):
                st.dup_counter += 1
                if st.dup_counter >= cfg.dup_window:
                    self._raise_risk(pid, "command", 0.2, s.tick, {"reason":"repeated_input", "count":st.dup_counter})
                    st.dup_counter = 0
        else:
            st.dup_counter = 0

    def _check_weapon(self, pid: int, st: PlayerState, s: TickSample) -> None:
        wc = self.cfg.weapon
        now_ms = s.server_recv_ts_ms
        if s.cmd_fire:
            rate = wc.fire_rate_hz.get(s.weapon_id, None)
            if rate:
                min_period_ms = 1000.0 / rate
                if st.last_fire_ts_ms is not None:
                    delta = now_ms - st.last_fire_ts_ms
                    if delta < min_period_ms * 0.9:  # allow 10% margin
                        self._raise_risk(pid, "weapon", min(1.0, (min_period_ms/delta)-1.0), s.tick, {"reason":"rof_too_high","delta_ms":delta,"min_ms":min_period_ms})
                st.last_fire_ts_ms = now_ms

        if s.cmd_reload:
            min_rl = wc.min_reload_s.get(s.weapon_id, None)
            if min_rl:
                if st.last_reload_ts_ms is not None:
                    delta = (now_ms - st.last_reload_ts_ms) / 1000.0
                    if delta < min_rl * 0.9:
                        self._raise_risk(pid, "weapon", 0.6, s.tick, {"reason":"reload_too_fast","delta_s":round(delta,3),"min_s":min_rl})
                st.last_reload_ts_ms = now_ms

    def _check_aim(self, pid: int, st: PlayerState, s: TickSample) -> None:
        ac = self.cfg.aim
        dt = self.cfg.movement.dt_s
        if st.last_yaw is not None and st.last_pitch is not None:
            # angular speed (deg/s)
            dyaw = self._ang_diff_deg(s.yaw_deg, st.last_yaw)
            dpit = s.pitch_deg - st.last_pitch
            ang_speed = math.sqrt(dyaw*dyaw + dpit*dpit) / dt
            # jerk (change of angular speed per s)
            jerk = (ang_speed - st.last_ang_speed) / dt
            if ang_speed > ac.max_angular_speed_deg_s:
                self._raise_risk(pid, "aim", min(1.0, (ang_speed/ac.max_angular_speed_deg_s)-1.0), s.tick, {"reason":"flick_speed","v":round(ang_speed,1)})
            if abs(jerk) > ac.max_angular_jerk_deg_s2:
                self._raise_risk(pid, "aim", min(1.0, (abs(jerk)/ac.max_angular_jerk_deg_s2)-1.0), s.tick, {"reason":"jerk","a":round(jerk,1)})
            # micro jitter floor: if long steady aiming without tiny variations while firing
            if s.cmd_fire and ang_speed < ac.micro_jitter_floor:
                self._raise_risk(pid, "aim", 0.3, s.tick, {"reason":"no_micro_jitter","v":round(ang_speed,6)})
            st.last_ang_speed = ang_speed
        st.last_yaw = s.yaw_deg
        st.last_pitch = s.pitch_deg

    def _check_lag(self, pid: int, st: PlayerState, s: TickSample) -> None:
        # Simple proxy: irregular server_recv_ts_ms deltas -> bursts after gaps
        # Keep last 10 inter-arrival times
        if not hasattr(st, "_arr_q"):
            st._arr_q = collections.deque(maxlen=10)  # type: ignore[attr-defined]
            st._last_arr_ms = s.server_recv_ts_ms     # type: ignore[attr-defined]
            return
        dt = s.server_recv_ts_ms - st._last_arr_ms   # type: ignore[attr-defined]
        st._last_arr_ms = s.server_recv_ts_ms        # type: ignore[attr-defined]
        st._arr_q.append(dt)                         # type: ignore[attr-defined]
        if len(st._arr_q) >= 5:                      # type: ignore[attr-defined]
            avg = sum(st._arr_q) / len(st._arr_q)    # type: ignore[attr-defined]
            # if many very small dt after a big gap -> lag switch suspicion
            small = sum(1 for x in st._arr_q if x < max(1, avg * 0.4))  # type: ignore[attr-defined]
            large = sum(1 for x in st._arr_q if x > avg * 2.5)          # type: ignore[attr-defined]
            if large >= 1 and small >= 3:
                self._raise_risk(pid, "lag", 0.5, s.tick, {"reason":"burst_after_gap","avg_ms":round(avg,1)})

    # ---- Risk & actions ----

    def _raise_risk(self, pid: int, category: str, score: float, tick: int, details: Dict[str, Any]) -> None:
        st = self.players.get(pid)
        if not st:
            return
        # Evidence
        st.evidence.add(tick, category, score, details)

        # EWMA per category
        alpha = self.cfg.scoring.ewma_alpha
        st.risk[category] = (1.0 - alpha) * st.risk.get(category, 0.0) + alpha * score

        # Threshold strike
        th = self.cfg.scoring.strike_thresholds.get(category, 1.0)
        if st.risk[category] >= th:
            # Add to total risk proportional to overflow
            overflow = st.risk[category] - th + 0.2
            st.total_risk += max(0.0, overflow)

    def _decay_total(self, st: PlayerState) -> None:
        now = time.monotonic()
        dt = max(0.0, now - st.last_risk_ts)
        st.last_risk_ts = now
        st.total_risk = max(0.0, st.total_risk - dt * self.cfg.scoring.decay_per_s)

    def _escalate(self, pid: int, st: PlayerState) -> Optional[str]:
        # Compute action based on total risk
        action = None
        for thr, act in self.cfg.scoring.actions:
            if st.total_risk >= thr:
                action = act
        return action

    # ---- Utilities ----

    @staticmethod
    def _ang_diff_deg(a: float, b: float) -> float:
        """Shortest yaw delta in degrees."""
        d = (a - b + 180.0) % 360.0 - 180.0
        return d

# =========================
# __all__
# =========================

__all__ = [
    # cfg
    "AntiCheatConfig","IntegrityConfig","MovementConfig","CommandConfig","WeaponConfig","AimConfig","ScoringConfig",
    # types
    "PacketEnvelope","TickSample",
    # core
    "AntiCheat","PlayerState",
    # evidence
    "EvidenceLog","EvidenceEntry",
    # utils
    "canonical_encode","fnv1a64",
]
