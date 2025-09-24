# engine-core/engine/ecs/systems/movement_system.py
"""
Industrial-grade Movement System for ECS.

Responsibilities:
- Fixed timestep integration with accumulator (stable determinism)
- Substepping with safe dt clamp to avoid explosions on frame spikes
- Global gravity vector (2D/3D aware), per-body gravity_scale support
- Velocity and position clamps (optional), world-bounds soft handling
- Sleep/wake respected via PhysicsBody logic
- CCD/collision hooks (interfaces) without engine lock-in
- Telemetry hooks for profiling/metrics without hard deps
- Deterministic ordering with optional stable sort
- Compatible with engine-core/engine/ecs/components/physics_body.py
- Optional use of engine-core/engine/clock.py SYSTEM_CLOCK

No external dependencies. Works sync; can be called from an async loop.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from engine.engine.ecs.components.physics_body import (
    PhysicsBody,
    vdim,
    vadd,
    vsub,
    vscale,
    vmin,
    vmax,
)

try:
    # Optional clock abstraction for better control in tests and scheduling
    from engine.engine.clock import SYSTEM_CLOCK, Clock
except Exception:  # pragma: no cover
    SYSTEM_CLOCK = None
    Clock = None  # type: ignore

_LOGGER = logging.getLogger("engine.ecs.movement")


Vec = Tuple[float, ...]


@dataclass(slots=True)
class MovementConfig:
    # Simulation step
    fixed_dt: float = 1.0 / 120.0           # base simulation step
    max_substeps: int = 8                   # hard cap on substeps per frame
    max_frame_dt: float = 0.25              # frame clamp to avoid spiral of death

    # Gravity (2D: (gx, gy); 3D: (gx, gy, gz))
    gravity: Vec = (0.0, -9.81, 0.0)

    # Clamps
    max_linear_speed: Optional[float] = 250.0
    max_angular_speed: Optional[float] = 50.0

    # World bounds (optional). If set, position will be softly clamped + zero velocity outside.
    # 2D: ((min_x,min_y),(max_x,max_y)), 3D: ((min_x,min_y,min_z),(max_x,max_y,max_z))
    world_bounds: Optional[Tuple[Vec, Vec]] = None

    # Behavior flags
    enable_ccd: bool = False                # enables CCD hook calls (swept tests via external collider)
    stable_order: bool = True               # stable deterministic order by entity_id
    disable_outside_world: bool = True      # zero out velocity/torque for out-of-bounds bodies

    # Telemetry
    telemetry_enabled: bool = True


@dataclass(slots=True)
class MovementStats:
    frame_dt: float = 0.0
    steps: int = 0
    bodies_processed: int = 0
    bodies_sleeping: int = 0
    bodies_out_of_bounds: int = 0


class CCDCollider:
    """
    Interface for CCD collision checks (optional).
    Engine should supply an implementation if enable_ccd=True.

    Methods should be cheap; system will call only for bodies with ccd=True.
    """

    def sweep(self, entity_id: int, start: Vec, end: Vec, radius_hint: float | None = None) -> Tuple[bool, Vec]:
        """
        Returns (hit, hit_point). If hit=False, hit_point may be end.
        Implementations may move to first impact point and let resolver fix response.
        """
        raise NotImplementedError


class MovementSystem:
    """
    Movement system that integrates PhysicsBody components at a fixed timestep.

    Integration uses semi-implicit Euler provided by PhysicsBody.integrate(dt, gravity).
    """

    def __init__(
        self,
        *,
        config: MovementConfig | None = None,
        clock: Clock | None = None,
        get_bodies: Callable[[], Iterable[PhysicsBody]] | None = None,
        ccd: Optional[CCDCollider] = None,
        on_step_begin: Optional[Callable[[MovementStats], None]] = None,
        on_step_end: Optional[Callable[[MovementStats], None]] = None,
    ) -> None:
        self.cfg = config or MovementConfig()
        self.clock = clock or SYSTEM_CLOCK
        self._accumulator = 0.0
        self._get_bodies = get_bodies or (lambda: ())
        self._ccd = ccd
        self._on_step_begin = on_step_begin
        self._on_step_end = on_step_end

        if self.clock is None:
            _LOGGER.warning("MovementSystem: no Clock provided; dt must be supplied explicitly to update()")

        self._last_frame_time: Optional[float] = None

    # -------------------------
    # Public API
    # -------------------------

    def update(self, dt: Optional[float] = None) -> MovementStats:
        """
        Update simulation by frame dt.
        - If dt is None: compute dt from clock.now/monotonic; requires clock.
        - Applies accumulator/substepping with cfg.fixed_dt and cfg.max_substeps.
        Returns aggregated MovementStats for the frame.
        """
        if dt is None:
            if self.clock is None:
                raise RuntimeError("dt is None and no clock provided")
            now = self.clock.monotonic()
            if self._last_frame_time is None:
                self._last_frame_time = now
                return MovementStats(frame_dt=0.0, steps=0, bodies_processed=0)
            dt = now - self._last_frame_time
            self._last_frame_time = now

        # Clamp pathological frame spikes
        dt = min(max(dt, 0.0), self.cfg.max_frame_dt)
        self._accumulator += dt

        stats = MovementStats(frame_dt=dt, steps=0, bodies_processed=0, bodies_sleeping=0, bodies_out_of_bounds=0)

        # Determine number of substeps
        step_dt = self.cfg.fixed_dt
        substeps = 0
        while self._accumulator + 1e-12 >= step_dt and substeps < self.cfg.max_substeps:
            self._integrate_step(step_dt, stats)
            self._accumulator -= step_dt
            substeps += 1
            stats.steps = substeps

        # If accumulator remains large (frame stall), drop excess to keep real-time
        if substeps == self.cfg.max_substeps and self._accumulator > step_dt:
            dropped = self._accumulator - step_dt
            self._accumulator = step_dt  # keep one step buffered
            if dropped > 0.0:
                _LOGGER.warning("MovementSystem: dropping accumulated dt=%.6f to maintain real-time", dropped)

        return stats

    # -------------------------
    # Internal
    # -------------------------

    def _iter_bodies(self) -> Iterable[PhysicsBody]:
        bodies = list(self._get_bodies())
        if self.cfg.stable_order:
            # Deterministic order by entity_id for reproducible simulations
            bodies.sort(key=lambda b: b.entity_id)
        return bodies

    def _integrate_step(self, dt: float, stats: MovementStats) -> None:
        gravity = self._normalized_gravity_for_scene()

        if self._on_step_begin and self.cfg.telemetry_enabled:
            try:
                self._on_step_begin(stats)
            except Exception:
                pass

        for body in self._iter_bodies():
            # Skip disabled collisions? Movement is independent; only skip if body static.
            if body.body_type.name == "STATIC":
                continue

            # Respect sleep
            if body.is_sleeping:
                stats.bodies_sleeping += 1
                continue

            # CCD pre-integration (optional): plan a sweep if enabled for this body
            if self.cfg.enable_ccd and self._ccd and body.ccd:
                self._ccd_pre_step(body, dt)

            # Integrate using component's logic (semi-implicit Euler, damping, sleep)
            body.integrate(dt, gravity=gravity)

            # Clamp velocities if configured
            self._clamp_velocities(body)

            # World bounds handling
            if self.cfg.world_bounds is not None:
                out = self._apply_world_bounds(body)
                if out:
                    stats.bodies_out_of_bounds += 1

            stats.bodies_processed += 1

        if self._on_step_end and self.cfg.telemetry_enabled:
            try:
                self._on_step_end(stats)
            except Exception:
                pass

    # -------------------------
    # Helpers
    # -------------------------

    def _normalized_gravity_for_scene(self) -> Vec:
        """
        Returns gravity vector consistent with bodies' dimensionality.
        If bodies include both 2D and 3D, we will pass appropriate slices during integrate().
        Here we keep a 3D default and rely on PhysicsBody.integrate slicing logic.
        """
        g = self.cfg.gravity
        # Ensure tuple of floats
        if len(g) == 2:
            return (float(g[0]), float(g[1]))
        if len(g) == 3:
            return (float(g[0]), float(g[1]), float(g[2]))
        # Fallback to 2D gravity if misconfigured
        return (0.0, -9.81)

    def _clamp_velocities(self, body: PhysicsBody) -> None:
        d = vdim(body.position)
        if self.cfg.max_linear_speed is not None:
            # Clamp component-wise to avoid sqrt; faster and stable
            max_v = float(self.cfg.max_linear_speed)
            lin = tuple(
                v if -max_v <= v <= max_v else (max_v if v > 0 else -max_v)
                for v in body.linear_velocity
            )
            body.linear_velocity = lin  # type: ignore

        if self.cfg.max_angular_speed is not None:
            max_w = float(self.cfg.max_angular_speed)
            if d == 2:
                w = body.angular_velocity[0]
                if w > max_w:
                    body.angular_velocity = (max_w,)
                elif w < -max_w:
                    body.angular_velocity = (-max_w,)
            else:
                body.angular_velocity = tuple(
                    (max_w if w > max_w else (-max_w if w < -max_w else w))
                    for w in body.angular_velocity
                )  # type: ignore

    def _apply_world_bounds(self, body: PhysicsBody) -> bool:
        """
        Softly clamps position into world bounds and optionally disables motion
        when far outside bounds (to avoid NaNs and runaway objects).
        Returns True if body was outside bounds.
        """
        assert self.cfg.world_bounds is not None
        (minp, maxp) = self.cfg.world_bounds
        d = vdim(body.position)
        # Normalize bounds for dim
        minp = tuple(minp[:d])  # type: ignore
        maxp = tuple(maxp[:d])  # type: ignore

        p = body.position
        was_out = False
        clamped = []
        for i in range(d):
            x = p[i]
            mn, mx = minp[i], maxp[i]
            if x < mn:
                x = mn
                was_out = True
            elif x > mx:
                x = mx
                was_out = True
            clamped.append(x)

        if was_out:
            body.position = tuple(clamped)  # type: ignore
            if self.cfg.disable_outside_world:
                # Zero linear/angular velocities and clear forces
                z = tuple(0.0 for _ in range(d))
                body.linear_velocity = z  # type: ignore
                body.angular_velocity = (0.0,) if d == 2 else (0.0, 0.0, 0.0)
                body.clear_forces()
        return was_out

    # -------------------------
    # CCD
    # -------------------------

    def _ccd_pre_step(self, body: PhysicsBody, dt: float) -> None:
        """
        Very light CCD hook: compute intended end position and ask collider to sweep.
        If collision reported, teleport to hit point and zero normal component later (resolver responsibility).
        """
        if not self._ccd:
            return
        d = vdim(body.position)
        start = body.position
        end = tuple(start[i] + body.linear_velocity[i] * dt for i in range(d))  # type: ignore
        try:
            hit, hit_point = self._ccd.sweep(body.entity_id, start, end, radius_hint=self._radius_hint(body))
        except Exception as e:  # pragma: no cover
            _LOGGER.error("CCD sweep failed for entity %s: %s", body.entity_id, e)
            return
        if hit:
            # Move to hit point and dampen velocity along path; collision response is outside of movement system
            body.teleport(hit_point, body.rotation)
            # Small damping to avoid tunneling after teleport; full resolution should be done by collision solver.
            body.linear_velocity = tuple(0.5 * v for v in body.linear_velocity)  # type: ignore

    @staticmethod
    def _radius_hint(body: PhysicsBody) -> float | None:
        # Provide approximate radius for CCD broad-phase (if engine can use it)
        st = body.shape.type.value
        if st == "sphere":
            return float(body.shape.params[0])
        if st == "box":
            # half-extents -> conservative circumscribed sphere radius
            he = body.shape.params
            if len(he) >= 2:
                acc = 0.0
                for x in he:
                    acc += (2.0 * x) ** 2
                return (acc ** 0.5) * 0.5
        return None


# -------------------------
# Convenience factory
# -------------------------

def make_movement_system(
    *,
    get_bodies: Callable[[], Iterable[PhysicsBody]],
    config: Optional[MovementConfig] = None,
    clock: Optional[Clock] = None,
    ccd: Optional[CCDCollider] = None,
    on_step_begin: Optional[Callable[[MovementStats], None]] = None,
    on_step_end: Optional[Callable[[MovementStats], None]] = None,
) -> MovementSystem:
    """
    Convenience factory to align with the rest of engine-core.
    """
    return MovementSystem(
        config=config,
        clock=clock,
        get_bodies=get_bodies,
        ccd=ccd,
        on_step_begin=on_step_begin,
        on_step_end=on_step_end,
    )


__all__ = [
    "Vec",
    "MovementConfig",
    "MovementStats",
    "CCDCollider",
    "MovementSystem",
    "make_movement_system",
]
