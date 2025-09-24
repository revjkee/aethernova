# engine-core/engine/ecs/systems/interest_management.py
"""
Industrial-grade Interest Management (Area of Interest, AoI) for ECS.

Features:
- Spatial hash grid (2D/3D) for scalable neighborhood queries
- Subscribers with AoI radius and hysteresis (enter/leave margins)
- LOD tiers by distance with per-tier update rates (Hz) and throttling
- Per-subscriber budgets: max updates per tick and byte budget
- Deterministic ordering (by entity_id, then priority)
- Delta sending via entity version provider (sends only when changed or forced)
- Optional Line-of-Sight (LoS) callback
- Flexible callbacks: on_enter/on_leave/on_update, estimate_size, get_priority, filters
- Safe clamps, validation, minimal allocations under load

This module is framework-agnostic and does not perform networking by itself.
Integrate with your transport by wiring the callbacks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Set, Tuple
import math
import time
import logging

_LOGGER = logging.getLogger("engine.ecs.interest")

# -----------------------------
# Basic math helpers
# -----------------------------

Vec = Tuple[float, ...]


def vdim(v: Vec) -> int:
    return len(v)


def dist2(a: Vec, b: Vec) -> float:
    return sum((x - y) * (x - y) for x, y in zip(a, b))


def clamp(x: float, lo: float, hi: float) -> float:
    return lo if x < lo else (hi if x > hi else x)


# -----------------------------
# Public config and types
# -----------------------------

@dataclass(slots=True)
class LODTier:
    """One distance tier with max distance and target rate."""
    max_distance: float       # inclusive upper bound in meters/units
    rate_hz: float            # send frequency for entities in this tier
    force_full_on_enter: bool = True  # send full snapshot on enter to this tier

    def interval_s(self) -> float:
        return 1.0 / self.rate_hz if self.rate_hz > 0 else float("inf")


@dataclass(slots=True)
class InterestConfig:
    # Spatial index
    dim: int = 3                           # 2 or 3
    cell_size: float = 8.0                 # spatial hash cell size
    conservative_insert_radius: float = 0.0  # extra radius for moving entities (broad-phase padding)

    # AoI and hysteresis
    default_aoi_radius: float = 64.0
    enter_margin: float = 2.0              # entities allowed to enter when dist <= aoi - enter_margin
    leave_margin: float = 4.0              # entities removed when dist >= aoi + leave_margin

    # LOD tiers (sorted by max_distance ascending)
    lod_tiers: Tuple[LODTier, ...] = (
        LODTier(max_distance=16.0, rate_hz=30.0),
        LODTier(max_distance=48.0, rate_hz=10.0),
        LODTier(max_distance=96.0, rate_hz=2.0),
    )

    # Budgets per subscriber per tick
    max_updates_per_tick: int = 256
    byte_budget_per_tick: int = 64 * 1024

    # Determinism and safety
    stable_order: bool = True
    max_entities_global: int = 2_000_000
    max_subscribers: int = 100_000

    # Telemetry flags
    log_budget_drops: bool = False


# Priority function type: higher is more important
PriorityFn = Callable[[int], int]
# Version provider: must be monotonic non-decreasing per entity
VersionFn = Callable[[int], int]
# Estimate serialized size for an update of a specific LOD level (bytes)
EstimateSizeFn = Callable[[int, int], int]
# Optional visibility filter to preclude entities even if in AoI (e.g., teams, cloaking)
VisibilityFilterFn = Callable[[int, int], bool]
# Optional per-subscriber per-entity last-minute veto/filter (e.g., muted)
SubscriberFilterFn = Callable[[int, int], bool]
# Optional Line-of-Sight check
LoSFn = Callable[[int, int, Vec, Vec], bool]
# Optional metrics hook
MetricHook = Callable[[str, Mapping[str, str] | None, Mapping[str, float] | None], None]
# Update encoder placeholder (your network layer will use it); returns opaque payload or None if suppressed
EncoderFn = Callable[[int, int, int], object]


# -----------------------------
# Spatial Hash Grid
# -----------------------------

class SpatialHash:
    """Uniform grid spatial index for fast AoI queries."""

    __slots__ = ("dim", "cell", "cells", "ents", "rpad")

    def __init__(self, dim: int, cell_size: float, conservative_insert_radius: float = 0.0) -> None:
        if dim not in (2, 3):
            raise ValueError("SpatialHash: dim must be 2 or 3")
        self.dim = dim
        self.cell = float(max(0.001, cell_size))
        self.rpad = float(max(0.0, conservative_insert_radius))
        self.cells: Dict[Tuple[int, ...], Set[int]] = {}
        self.ents: Dict[int, Tuple[Vec, float]] = {}  # id -> (pos, radius)

    # Cell math
    def _key(self, p: Vec) -> Tuple[int, ...]:
        return tuple(int(math.floor(p[i] / self.cell)) for i in range(self.dim))

    def _aabb_keys(self, center: Vec, radius: float) -> Iterable[Tuple[int, ...]]:
        r = radius + self.rpad
        mins = [int(math.floor((center[i] - r) / self.cell)) for i in range(self.dim)]
        maxs = [int(math.floor((center[i] + r) / self.cell)) for i in range(self.dim)]
        if self.dim == 2:
            for x in range(mins[0], maxs[0] + 1):
                for y in range(mins[1], maxs[1] + 1):
                    yield (x, y)
        else:
            for x in range(mins[0], maxs[0] + 1):
                for y in range(mins[1], maxs[1] + 1):
                    for z in range(mins[2], maxs[2] + 1):
                        yield (x, y, z)

    # Entity ops
    def upsert(self, eid: int, pos: Vec, radius: float = 0.0) -> None:
        old = self.ents.get(eid)
        if old is not None:
            self.remove(eid)
        self.ents[eid] = (pos, float(max(0.0, radius)))
        for key in self._aabb_keys(pos, radius):
            self.cells.setdefault(key, set()).add(eid)

    def move(self, eid: int, new_pos: Vec, radius: Optional[float] = None) -> None:
        old = self.ents.get(eid)
        if old is None:
            self.upsert(eid, new_pos, radius or 0.0)
            return
        old_pos, old_r = old
        r = old_r if radius is None else float(max(0.0, radius))
        # quick reject if remains within same covered cells
        old_keys = set(self._aabb_keys(old_pos, r))
        new_keys = set(self._aabb_keys(new_pos, r))
        if old_keys != new_keys:
            for k in old_keys - new_keys:
                cs = self.cells.get(k)
                if cs:
                    cs.discard(eid)
                    if not cs:
                        self.cells.pop(k, None)
            for k in new_keys - old_keys:
                self.cells.setdefault(k, set()).add(eid)
        self.ents[eid] = (new_pos, r)

    def remove(self, eid: int) -> None:
        val = self.ents.pop(eid, None)
        if val is None:
            return
        pos, r = val
        for key in self._aabb_keys(pos, r):
            cs = self.cells.get(key)
            if cs:
                cs.discard(eid)
                if not cs:
                    self.cells.pop(key, None)

    def query(self, center: Vec, radius: float) -> Iterable[int]:
        # Coarse cell query; refine by distance outside.
        rr = radius + self.rpad
        rr2 = rr * rr
        for key in self._aabb_keys(center, rr):
            for eid in self.cells.get(key, ()):
                pos, _ = self.ents.get(eid, (center, 0.0))
                if dist2(pos, center) <= rr2:
                    yield eid


# -----------------------------
# Subscriber state
# -----------------------------

@dataclass(slots=True)
class Subscriber:
    sid: int
    position: Vec
    aoi_radius: float
    # Optional facing cone (radians); if None -> no FOV filter
    fov_dir: Optional[Vec] = None
    fov_cos_half_angle: Optional[float] = None  # cos(half_angle)
    # Custom per-subscriber limits (override config)
    max_updates_per_tick: Optional[int] = None
    byte_budget_per_tick: Optional[int] = None


@dataclass(slots=True)
class _SeenInfo:
    tier_idx: int
    next_due_ts: float
    last_version: int


@dataclass(slots=True)
class _SubState:
    sub: Subscriber
    visible: Set[int] = field(default_factory=set)          # currently in visibility set
    seen: Dict[int, _SeenInfo] = field(default_factory=dict)  # eid -> info


# -----------------------------
# Interest Manager
# -----------------------------

class InterestManager:
    """
    Manages AoI visibility sets and per-subscriber update scheduling.
    """

    def __init__(
        self,
        *,
        config: InterestConfig = InterestConfig(),
        priority_fn: Optional[PriorityFn] = None,
        version_fn: Optional[VersionFn] = None,
        estimate_size_fn: Optional[EstimateSizeFn] = None,
        visibility_filter: Optional[VisibilityFilterFn] = None,
        subscriber_filter: Optional[SubscriberFilterFn] = None,
        los_fn: Optional[LoSFn] = None,
        encoder_fn: Optional[EncoderFn] = None,
        metrics: Optional[MetricHook] = None,
        now_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        self.cfg = config
        self.grid = SpatialHash(dim=config.dim, cell_size=config.cell_size,
                                conservative_insert_radius=config.conservative_insert_radius)
        self.subs: Dict[int, _SubState] = {}

        self.priority_fn = priority_fn or (lambda eid: 0)
        self.version_fn = version_fn or (lambda eid: 0)
        self.estimate_size_fn = estimate_size_fn or (lambda eid, tier: 128)
        self.visibility_filter = visibility_filter or (lambda sub_id, eid: True)
        self.subscriber_filter = subscriber_filter or (lambda sub_id, eid: True)
        self.los_fn = los_fn
        self.encoder_fn = encoder_fn or (lambda eid, tier, version: {"id": eid, "tier": tier, "v": version})
        self.metrics = metrics
        self.now = now_fn

        # Entities registry (minimal): position and optional personal radius for broad-phase padding
        self.entities: Dict[int, Tuple[Vec, float]] = {}

    # -------- Entity ops --------

    def upsert_entity(self, eid: int, position: Vec, radius: float = 0.0) -> None:
        if len(self.entities) >= self.cfg.max_entities_global and eid not in self.entities:
            raise RuntimeError("InterestManager: global entity limit reached")
        pos = self._normalize_pos(position)
        self.entities[eid] = (pos, float(max(0.0, radius)))
        self.grid.upsert(eid, pos, radius)

    def move_entity(self, eid: int, position: Vec) -> None:
        pos = self._normalize_pos(position)
        self.entities[eid] = (pos, self.entities.get(eid, (pos, 0.0))[1])
        self.grid.move(eid, pos, None)

    def remove_entity(self, eid: int) -> None:
        self.entities.pop(eid, None)
        self.grid.remove(eid)
        # Remove from all subscribers' states
        for st in self.subs.values():
            st.visible.discard(eid)
            st.seen.pop(eid, None)

    # -------- Subscriber ops --------

    def register_subscriber(self, sub: Subscriber) -> None:
        if len(self.subs) >= self.cfg.max_subscribers and sub.sid not in self.subs:
            raise RuntimeError("InterestManager: subscriber limit reached")
        sub.aoi_radius = float(max(0.0, sub.aoi_radius or self.cfg.default_aoi_radius))
        sub.position = self._normalize_pos(sub.position)
        self.subs[sub.sid] = _SubState(sub=sub)

    def update_subscriber(self, sid: int, position: Optional[Vec] = None, aoi_radius: Optional[float] = None,
                          fov_dir: Optional[Vec] = None, fov_cos_half_angle: Optional[float] = None) -> None:
        st = self.subs.get(sid)
        if not st:
            return
        if position is not None:
            st.sub.position = self._normalize_pos(position)
        if aoi_radius is not None:
            st.sub.aoi_radius = float(max(0.0, aoi_radius))
        if fov_dir is not None:
            st.sub.fov_dir = self._normalize_dir(fov_dir)
        if fov_cos_half_angle is not None:
            st.sub.fov_cos_half_angle = float(clamp(fov_cos_half_angle, -1.0, 1.0))

    def unregister_subscriber(self, sid: int) -> None:
        self.subs.pop(sid, None)

    # -------- Tick --------

    def tick(self) -> Dict[int, Dict[str, List[object]]]:
        """
        Advance scheduling by one frame/tick.
        Returns per-subscriber batches:
           { sid: { "enter": [payload...], "leave": [payload...], "update": [payload...] } }
        Payload objects are produced by encoder_fn.
        """
        now = self.now()
        batches: Dict[int, Dict[str, List[object]]] = {}

        # Deterministic iteration over subscribers
        for sid in sorted(self.subs.keys()):
            st = self.subs[sid]
            sub = st.sub
            batch = {"enter": [], "leave": [], "update": []}
            batches[sid] = batch

            # 1) Compute candidates with hysteresis
            enter_set, leave_set = self._compute_visibility_diff(st)

            # 2) Apply LoS and filters for enters
            if enter_set:
                filtered_enter = []
                for eid in enter_set:
                    if not self._passes_filters(sub.sid, eid, entering=True):
                        continue
                    if self._violates_fov(sub, eid):
                        continue
                    if self.los_fn and not self._passes_los(sub.sid, eid):
                        continue
                    filtered_enter.append(eid)
                enter_set = filtered_enter

            # 3) Apply leaves immediately (no filters)
            for eid in leave_set:
                st.visible.discard(eid)
                st.seen.pop(eid, None)
                # Encode leave (no LOD needed)
                payload = self.encoder_fn(eid, -1, self.version_fn(eid))
                batch["leave"].append(payload)

            # 4) Commit enters and initialize seen state
            for eid in enter_set:
                st.visible.add(eid)
                tier_idx = self._tier_for(sub, eid)
                v = self.version_fn(eid)
                next_due = now if self.cfg.lod_tiers[tier_idx].force_full_on_enter else (now + self.cfg.lod_tiers[tier_idx].interval_s())
                st.seen[eid] = _SeenInfo(tier_idx=tier_idx, next_due_ts=next_due, last_version=v)
                # Full snapshot on enter
                payload = self.encoder_fn(eid, tier_idx, v)
                batch["enter"].append(payload)

            # 5) Schedule updates for visible entities respecting budgets
            self._schedule_updates(st, now, batch)

        return batches

    # -----------------------------
    # Internal helpers
    # -----------------------------

    def _normalize_pos(self, p: Vec) -> Vec:
        if self.cfg.dim == 2:
            if len(p) < 2:
                raise ValueError("position must have at least 2 components")
            return (float(p[0]), float(p[1]))
        if len(p) < 3:
            raise ValueError("position must have at least 3 components")
        return (float(p[0]), float(p[1]), float(p[2]))

    def _normalize_dir(self, d: Vec) -> Vec:
        # Normalize a direction vector
        if self.cfg.dim == 2:
            x, y = d[:2]
            n = math.hypot(x, y)
            return (x / n, y / n) if n > 0 else (1.0, 0.0)
        x, y, z = d[:3]
        n = math.sqrt(x * x + y * y + z * z)
        return (x / n, y / n, z / n) if n > 0 else (1.0, 0.0, 0.0)

    def _passes_filters(self, sid: int, eid: int, *, entering: bool) -> bool:
        if not self.visibility_filter(sid, eid):
            return False
        if not self.subscriber_filter(sid, eid):
            return False
        return True

    def _violates_fov(self, sub: Subscriber, eid: int) -> bool:
        # If FOV specified, drop if outside cone
        if sub.fov_dir is None or sub.fov_cos_half_angle is None:
            return False
        ep, _ = self.entities.get(eid, (sub.position, 0.0))
        dir_vec = tuple(ep[i] - sub.position[i] for i in range(self.cfg.dim))
        # Normalize quickly
        mag = math.sqrt(sum(c * c for c in dir_vec))
        if mag <= 1e-12:
            return False
        dir_unit = tuple(c / mag for c in dir_vec)
        dot = sum(dir_unit[i] * sub.fov_dir[i] for i in range(self.cfg.dim))
        return dot < sub.fov_cos_half_angle

    def _passes_los(self, sid: int, eid: int) -> bool:
        if not self.los_fn:
            return True
        sub = self.subs[sid].sub
        ep, _ = self.entities.get(eid, (sub.position, 0.0))
        return self.los_fn(sid, eid, sub.position, ep)

    def _compute_visibility_diff(self, st: _SubState) -> Tuple[List[int], List[int]]:
        sub = st.sub
        # Enter threshold is slightly smaller; leave threshold is larger (hysteresis)
        r_enter = max(0.0, sub.aoi_radius - self.cfg.enter_margin)
        r_leave = sub.aoi_radius + self.cfg.leave_margin

        # Candidate enters from spatial index
        candidates = set(self.grid.query(sub.position, r_enter))

        # Remove self if subscriber is also an entity
        candidates.discard(sub.sid)

        # New enters = candidates - already visible
        enters = [eid for eid in candidates if eid not in st.visible]

        # Leaves = visible that are outside leave radius OR filtered out now
        leaves: List[int] = []
        rleave2 = r_leave * r_leave
        for eid in list(st.visible):
            ep, _ = self.entities.get(eid, (sub.position, 0.0))
            if dist2(ep, sub.position) >= rleave2:
                leaves.append(eid)

        return enters, leaves

    def _tier_for(self, sub: Subscriber, eid: int) -> int:
        ep, _ = self.entities.get(eid, (sub.position, 0.0))
        d = math.sqrt(dist2(ep, sub.position))
        tiers = self.cfg.lod_tiers
        for i, t in enumerate(tiers):
            if d <= t.max_distance:
                return i
        return len(tiers) - 1

    def _schedule_updates(self, st: _SubState, now: float, batch: Dict[str, List[object]]) -> None:
        sub = st.sub
        max_updates = sub.max_updates_per_tick if sub.max_updates_per_tick is not None else self.cfg.max_updates_per_tick
        byte_budget = sub.byte_budget_per_tick if sub.byte_budget_per_tick is not None else self.cfg.byte_budget_per_tick

        # Candidates: visible entities sorted by priority, then id for determinism
        # Only consider entities that pass subscriber_filter (runtime) and LoS (optional) to avoid wasted budget
        visible_sorted = sorted(
            (eid for eid in st.visible if self._passes_filters(sub.sid, eid, entering=False) and (not self.los_fn or self._passes_los(sub.sid, eid))),
            key=lambda eid: (-self.priority_fn(eid), eid),
        )

        sent_count = 0
        sent_bytes = 0

        for eid in visible_sorted:
            if sent_count >= max_updates or sent_bytes >= byte_budget:
                if self.cfg.log_budget_drops and (sent_count >= max_updates or sent_bytes >= byte_budget):
                    _LOGGER.debug("Budget ex_
