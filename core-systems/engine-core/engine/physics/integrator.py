# -*- coding: utf-8 -*-
"""
engine-core / engine / physics / integrator.py

Industrial-grade physics integrators with deterministic behavior.

Features:
- Integrators: ExplicitEuler, SemiImplicitEuler (symplectic), Verlet, VelocityVerlet, RK4, RK45 (Cash–Karp) with adaptive dt
- Substepping and speed clamp for stability
- Global gravity, linear drag (air resistance), per-body damping
- External force providers via callbacks; additive force accumulation per step
- Thread-safe-free by design (call from main simulation thread)
- Observability hooks (on_step_start, on_step_end, on_body_post)
- Energy diagnostics (kinetic + simple gravitational potential if gravity is uniform)
- Snapshot/restore of system state
- No external dependencies; portable

Coordinate type: sequence[float] of dimension D (2D/3D/ND) consistent per system.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Literal, Any
from math import sqrt, isfinite, exp

Vec = List[float]
IntegratorName = Literal[
    "explicit_euler",
    "semi_implicit_euler",
    "verlet",
    "velocity_verlet",
    "rk4",
    "rk45",
]

__all__ = [
    "Body",
    "BodyState",
    "PhysicsSystem",
    "IntegratorConfig",
    "Integrator",
    "make_integrator",
    "clamp",
]

# ============================================================
# Utilities
# ============================================================

def clamp(x: float, lo: float, hi: float) -> float:
    return lo if x < lo else hi if x > hi else x

def v_zero(d: int) -> Vec:
    return [0.0] * d

def v_add(a: Sequence[float], b: Sequence[float]) -> Vec:
    return [float(x) + float(y) for x, y in zip(a, b)]

def v_sub(a: Sequence[float], b: Sequence[float]) -> Vec:
    return [float(x) - float(y) for x, y in zip(a, b)]

def v_scale(a: Sequence[float], s: float) -> Vec:
    s = float(s)
    return [float(x) * s for x in a]

def v_dot(a: Sequence[float], b: Sequence[float]) -> float:
    return sum(float(x) * float(y) for x, y in zip(a, b))

def v_norm(a: Sequence[float]) -> float:
    return sqrt(v_dot(a, a))

def v_check(a: Sequence[float]) -> None:
    for x in a:
        if not isfinite(float(x)):
            raise ValueError("non-finite vector component")

def v_copy(a: Sequence[float]) -> Vec:
    return [float(x) for x in a]

# ============================================================
# Data model
# ============================================================

@dataclass
class Body:
    """
    Physical body with position/velocity; only linear motion (no rotation).
    """
    id: str
    mass: float
    pos: Vec
    vel: Vec
    damping: float = 0.0          # [1/s] exponential velocity damping; 0 = none
    drag: float = 0.0             # linear drag coefficient c in F = -c * v
    max_speed: Optional[float] = None
    # Internals
    _acc_tmp: Vec = field(default_factory=list, repr=False)  # scratch
    _prev_pos: Optional[Vec] = field(default=None, repr=False)  # for Verlet

    def __post_init__(self) -> None:
        if self.mass <= 0.0:
            raise ValueError("mass must be > 0")
        if len(self.pos) != len(self.vel):
            raise ValueError("pos/vel dimension mismatch")
        v_check(self.pos); v_check(self.vel)
        if not self._acc_tmp:
            self._acc_tmp = v_zero(len(self.pos))

@dataclass
class BodyState:
    pos: Vec
    vel: Vec
    mass: float

ForceProvider = Callable[[float, "PhysicsSystem", BodyState], Vec]

@dataclass
class PhysicsSystem:
    """
    Container holding bodies and global environment.
    """
    dimension: int
    gravity: Vec = field(default_factory=lambda: [0.0, -9.81, 0.0])  # default Y-down 3D; trimmed by dimension at runtime
    bodies: List[Body] = field(default_factory=list)
    force_providers: List[ForceProvider] = field(default_factory=list)  # additive forces per body per substep
    # observability hooks
    on_step_start: Optional[Callable[[float, float], None]] = None
    on_step_end: Optional[Callable[[float, float], None]] = None
    on_body_post: Optional[Callable[[Body, float, float], None]] = None  # after each body update

    def __post_init__(self) -> None:
        if self.dimension <= 0:
            raise ValueError("dimension must be >= 1")
        self.gravity = [float(x) for x in self.gravity[: self.dimension]] + [0.0] * max(0, self.dimension - len(self.gravity))

    def add_body(self, body: Body) -> None:
        if len(body.pos) != self.dimension or len(body.vel) != self.dimension:
            raise ValueError("body dimension mismatch")
        self.bodies.append(body)

    def clear_forces(self) -> None:
        # no persistent accumulation; forces are recomputed each substep
        pass

    def compute_net_force(self, t: float, body: Body) -> Vec:
        """
        Sum of external forces: gravity (as F = m*g), drag, user providers.
        """
        # gravity
        F = v_scale(self.gravity, body.mass)
        # linear drag
        if body.drag > 0.0:
            F = v_add(F, v_scale(body.vel, -float(body.drag)))
        # external providers
        if self.force_providers:
            bs = BodyState(pos=body.pos, vel=body.vel, mass=body.mass)
            for fp in self.force_providers:
                f = fp(t, self, bs)
                if len(f) != self.dimension:
                    raise ValueError("force provider dimension mismatch")
                F = v_add(F, f)
        return F

    # --- Diagnostics ---
    def kinetic_energy(self) -> float:
        return sum(0.5 * b.mass * v_dot(b.vel, b.vel) for b in self.bodies)

    def potential_energy_gravity(self) -> float:
        # For uniform gravity g, choose axis as provided; PE = -m * g · r
        return sum(-b.mass * v_dot(self.gravity, b.pos) for b in self.bodies)

    def snapshot(self) -> Dict[str, Any]:
        return {
            "dimension": self.dimension,
            "gravity": list(self.gravity),
            "bodies": [
                {
                    "id": b.id,
                    "mass": b.mass,
                    "pos": list(b.pos),
                    "vel": list(b.vel),
                    "damping": b.damping,
                    "drag": b.drag,
                    "max_speed": b.max_speed,
                    "_prev_pos": None if b._prev_pos is None else list(b._prev_pos),
                }
                for b in self.bodies
            ],
        }

    @staticmethod
    def restore(data: Dict[str, Any]) -> "PhysicsSystem":
        sys = PhysicsSystem(dimension=int(data["dimension"]), gravity=[float(x) for x in data["gravity"]])
        for bd in data.get("bodies", []):
            b = Body(
                id=str(bd["id"]),
                mass=float(bd["mass"]),
                pos=[float(x) for x in bd["pos"]],
                vel=[float(x) for x in bd["vel"]],
                damping=float(bd.get("damping", 0.0)),
                drag=float(bd.get("drag", 0.0)),
                max_speed=(None if bd.get("max_speed") is None else float(bd["max_speed"])),
            )
            if bd.get("_prev_pos") is not None:
                b._prev_pos = [float(x) for x in bd["_prev_pos"]]
            sys.add_body(b)
        return sys

# ============================================================
# Integrator core and config
# ============================================================

@dataclass
class IntegratorConfig:
    name: IntegratorName = "velocity_verlet"
    substeps: int = 1               # integer substeps per frame (applies to all schemes)
    dt_min: float = 1e-5
    dt_max: float = 1 / 20.0
    adaptive: bool = False          # only meaningful for rk45
    tol_abs: float = 1e-5
    tol_rel: float = 1e-3
    growth_limit: float = 2.0       # max dt growth per accepted step (rk45)
    shrink_limit: float = 0.25      # min dt shrink factor on reject (rk45)
    speed_clamp: Optional[float] = None  # hard speed cap per body (post integration)

class Integrator:
    """
    Integrator coordinating stepping logic and selecting scheme.
    """

    def __init__(self, cfg: IntegratorConfig) -> None:
        self.cfg = cfg
        self._scheme = cfg.name
        self._last_status: Dict[str, Any] = {}

    # Public API
    def step(self, sys: PhysicsSystem, t: float, dt: float) -> Tuple[float, Dict[str, Any]]:
        """
        Advance system by dt (seconds). Returns (actual_dt_spent, status).
        If cfg.adaptive and scheme == rk45, dt may be subdivided adaptively.
        Otherwise, evenly splits by substeps.
        """
        if sys.on_step_start:
            try:
                sys.on_step_start(t, dt)
            except Exception:
                pass

        spent = 0.0
        status = {"substeps": 0, "rejected": 0, "scheme": self._scheme}

        if self._scheme == "rk45" and self.cfg.adaptive:
            # Adaptive integration over [t, t+dt]
            target = dt
            while spent < target - 1e-12:
                rem = target - spent
                h = clamp(rem, self.cfg.dt_min, min(self.cfg.dt_max, rem))
                accepted, used, err_est = self._rk45_adaptive_step(sys, t + spent, h)
                if not accepted:
                    status["rejected"] += 1
                    continue
                spent += used
                status["substeps"] += 1
                if sys.on_step_end:
                    try:
                        sys.on_step_end(t + spent, used)
                    except Exception:
                        pass
        else:
            # Fixed substepping
            n = max(1, int(self.cfg.substeps))
            h = max(self.cfg.dt_min, min(self.cfg.dt_max, dt)) / n
            for _ in range(n):
                self._fixed_step(sys, t + spent, h)
                spent += h
                status["substeps"] += 1
                if sys.on_step_end:
                    try:
                        sys.on_step_end(t + spent, h)
                    except Exception:
                        pass

        self._last_status = status
        return spent, status

    def last_status(self) -> Dict[str, Any]:
        return dict(self._last_status)

    # --------------------------------------------------------
    # Fixed-step dispatch
    # --------------------------------------------------------

    def _fixed_step(self, sys: PhysicsSystem, t: float, h: float) -> None:
        name = self._scheme
        if name == "explicit_euler":
            self._explicit_euler(sys, t, h)
        elif name == "semi_implicit_euler":
            self._semi_implicit_euler(sys, t, h)
        elif name == "verlet":
            self._verlet(sys, t, h)
        elif name == "velocity_verlet":
            self._velocity_verlet(sys, t, h)
        elif name == "rk4":
            self._rk4(sys, t, h)
        elif name == "rk45":
            # non-adaptive single RK45 step = RK4 fidelity with embedded error (ignored)
            self._rk45_single(sys, t, h)
        else:
            raise ValueError(f"unknown integrator: {name}")

    # --------------------------------------------------------
    # Schemes
    # --------------------------------------------------------

    def _apply_damping_and_clamp(self, b: Body, h: float) -> None:
        # Exponential velocity damping (per-second rate -> per step factor)
        if b.damping > 0.0:
            factor = exp(-b.damping * h)
            b.vel = v_scale(b.vel, factor)
        # Clamp speed
        cap = self.cfg.speed_clamp or b.max_speed
        if cap is not None and cap > 0.0:
            speed = v_norm(b.vel)
            if speed > cap:
                b.vel = v_scale(b.vel, cap / speed)

    def _explicit_euler(self, sys: PhysicsSystem, t: float, h: float) -> None:
        for b in sys.bodies:
            F = sys.compute_net_force(t, b)
            a = v_scale(F, 1.0 / b.mass)
            b.pos = v_add(b.pos, v_scale(b.vel, h))
            b.vel = v_add(b.vel, v_scale(a, h))
            self._apply_damping_and_clamp(b, h)
            if sys.on_body_post:
                sys.on_body_post(b, t, h)

    def _semi_implicit_euler(self, sys: PhysicsSystem, t: float, h: float) -> None:
        for b in sys.bodies:
            F = sys.compute_net_force(t, b)
            a = v_scale(F, 1.0 / b.mass)
            b.vel = v_add(b.vel, v_scale(a, h))     # update velocity first
            b.pos = v_add(b.pos, v_scale(b.vel, h)) # then position
            self._apply_damping_and_clamp(b, h)
            if sys.on_body_post:
                sys.on_body_post(b, t, h)

    def _verlet(self, sys: PhysicsSystem, t: float, h: float) -> None:
        # Position Verlet with cached previous position; initializes from current vel on first run
        h2 = h * h
        for b in sys.bodies:
            F = sys.compute_net_force(t, b)
            a = v_scale(F, 1.0 / b.mass)
            if b._prev_pos is None:
                # initialize prev_pos: x_{-1} = x_0 - v_0 * h
                b._prev_pos = v_sub(b.pos, v_scale(b.vel, h))
            new_pos = v_add(v_sub(v_scale(b.pos, 2.0), b._prev_pos), v_scale(a, h2))
            # velocity estimate (central difference)
            new_vel = v_scale(v_sub(new_pos, b._prev_pos), 1.0 / (2.0 * h))
            b._prev_pos, b.pos, b.vel = b.pos, new_pos, new_vel
            self._apply_damping_and_clamp(b, h)
            if sys.on_body_post:
                sys.on_body_post(b, t, h)

    def _velocity_verlet(self, sys: PhysicsSystem, t: float, h: float) -> None:
        # a(t)
        accs: List[Vec] = []
        for b in sys.bodies:
            F = sys.compute_net_force(t, b)
            accs.append(v_scale(F, 1.0 / b.mass))
        # x_{t+h} = x_t + v_t h + 0.5 a_t h^2
        h2 = 0.5 * h * h
        for i, b in enumerate(sys.bodies):
            b.pos = v_add(b.pos, v_add(v_scale(b.vel, h), v_scale(accs[i], h2)))
        # a(t+h) and v update: v_{t+h} = v_t + 0.5 (a_t + a_{t+h}) h
        accs_next: List[Vec] = []
        for b in sys.bodies:
            F_next = sys.compute_net_force(t + h, b)
            accs_next.append(v_scale(F_next, 1.0 / b.mass))
        for i, b in enumerate(sys.bodies):
            b.vel = v_add(b.vel, v_scale(v_add(accs[i], accs_next[i]), 0.5 * h))
            self._apply_damping_and_clamp(b, h)
            if sys.on_body_post:
                sys.on_body_post(b, t, h)

    def _rk4(self, sys: PhysicsSystem, t: float, h: float) -> None:
        # Convert 2nd order system to 1st order: y = [pos, vel]
        d = sys.dimension
        for b in sys.bodies:
            y0 = v_copy(b.pos) + v_copy(b.vel)

            def deriv(tau: float, y: Sequence[float]) -> Vec:
                pos = list(y[:d]); vel = list(y[d:])
                # forces at (pos, vel)
                tmp = Body(id=b.id, mass=b.mass, pos=pos, vel=vel, damping=b.damping, drag=b.drag, max_speed=b.max_speed)
                F = sys.compute_net_force(tau, tmp)
                a = v_scale(F, 1.0 / b.mass)
                return vel + a

            k1 = deriv(t, y0)
            k2 = deriv(t + 0.5 * h, v_add(y0, v_scale(k1, 0.5 * h)))
            k3 = deriv(t + 0.5 * h, v_add(y0, v_scale(k2, 0.5 * h)))
            k4 = deriv(t + h, v_add(y0, v_scale(k3, h)))

            y = v_add(y0, v_scale(v_add(v_add(k1, v_scale(k2, 2.0)), v_add(v_scale(k3, 2.0), k4)), h / 6.0))
            b.pos = list(y[:d]); b.vel = list(y[d:])
            self._apply_damping_and_clamp(b, h)
            if sys.on_body_post:
                sys.on_body_post(b, t, h)

    # ---- RK45 (Cash–Karp) single step (no adapt) ----
    def _rk45_single(self, sys: PhysicsSystem, t: float, h: float) -> None:
        d = sys.dimension
        for b in sys.bodies:
            y0 = v_copy(b.pos) + v_copy(b.vel)

            def deriv(tau: float, y: Sequence[float]) -> Vec:
                pos = list(y[:d]); vel = list(y[d:])
                tmp = Body(id=b.id, mass=b.mass, pos=pos, vel=vel, damping=b.damping, drag=b.drag, max_speed=b.max_speed)
                F = sys.compute_net_force(tau, tmp)
                a = v_scale(F, 1.0 / b.mass)
                return vel + a

            y4, _err = _rkck_step(deriv, t, y0, h)  # ignore error here
            b.pos = list(y4[:d]); b.vel = list(y4[d:])
            self._apply_damping_and_clamp(b, h)
            if sys.on_body_post:
                sys.on_body_post(b, t, h)

    # ---- RK45 adaptive over single step h (accept/reject logic applied) ----
    def _rk45_adaptive_step(self, sys: PhysicsSystem, t: float, h: float) -> Tuple[bool, float, float]:
        # Try adaptive step for all bodies simultaneously; if any rejects, shrink and retry.
        # For determinism, we compute a shared error metric as max over bodies.
        d = sys.dimension
        tol_abs = self.cfg.tol_abs
        tol_rel = self.cfg.tol_rel
        growth = self.cfg.growth_limit
        shrink = self.cfg.shrink_limit

        # Prepare body states
        y0_all: List[List[float]] = []
        bodies = sys.bodies

        def mk_tmp(b: Body, y: Sequence[float]) -> Body:
            pos = list(y[:d]); vel = list(y[d:])
            return Body(id=b.id, mass=b.mass, pos=pos, vel=vel, damping=b.damping, drag=b.drag, max_speed=b.max_speed)

        def deriv_factory(b: Body) -> Callable[[float, Sequence[float]], Vec]:
            def deriv(tau: float, y: Sequence[float]) -> Vec:
                tmpb = mk_tmp(b, y)
                F = sys.compute_net_force(tau, tmpb)
                a = v_scale(F, 1.0 / b.mass)
                return list(y[d:]) + a
            return deriv

        # Run Cash–Karp per body; collect errors
        max_err_ratio = 0.0
        y4_all: List[List[float]] = []
        for b in bodies:
            y0 = v_copy(b.pos) + v_copy(b.vel)
            y4, err = _rkck_step(deriv_factory(b), t, y0, h)
            # error norm (scaled)
            sc = [tol_abs + tol_rel * max(abs(yi), abs(yi4)) for yi, yi4 in zip(y0, y4)]
            err_norm = max(abs(e) / s for e, s in zip(err, sc))
            if not isfinite(err_norm):
                err_norm = float("inf")
            max_err_ratio = max(max_err_ratio, err_norm)
            y0_all.append(y0)
            y4_all.append(y4)

        if max_err_ratio <= 1.0:
            # Accept; write back and clamp/damp
            for b, y4 in zip(bodies, y4_all):
                b.pos = list(y4[:d]); b.vel = list(y4[d:])
                self._apply_damping_and_clamp(b, h)
                if sys.on_body_post:
                    sys.on_body_post(b, t, h)
            # suggest next h
            if max_err_ratio == 0.0:
                factor = growth
            else:
                factor = clamp(0.9 * (1.0 / max_err_ratio) ** 0.2, 1.0 / growth, growth)
            used = clamp(h * factor, self.cfg.dt_min, self.cfg.dt_max)
            return True, h, max_err_ratio
        else:
            # Reject; shrink h and retry by outer loop
            factor = max(shrink, clamp(0.9 * (1.0 / max_err_ratio) ** 0.25, shrink, 1.0))
            new_h = clamp(h * factor, self.cfg.dt_min, h * 0.5)
            # Update dt_max to encourage convergence for this frame
            self.cfg.dt_max = min(self.cfg.dt_max, new_h)
            return False, 0.0, max_err_ratio

# ============================================================
# Cash–Karp RK45 kernel (embedded 4(5))
# ============================================================

def _rkck_step(f: Callable[[float, Sequence[float]], Vec], t: float, y: Sequence[float], h: float) -> Tuple[Vec, Vec]:
    """
    One Cash–Karp step. Returns (y4, error_vector) where y4 is 4th-order solution.
    Coefficients from Cash & Karp 1990.
    """
    # Butcher tableau coefficients
    a2 = 1/5
    a3 = 3/10
    a4 = 3/5
    a5 = 1.0
    a6 = 7/8

    b21 = 1/5

    b31 = 3/40;      b32 = 9/40

    b41 = 3/10;      b42 = -9/10;       b43 = 6/5

    b51 = -11/54;    b52 = 5/2;         b53 = -70/27;    b54 = 35/27

    b61 = 1631/55296; b62 = 175/512;    b63 = 575/13824; b64 = 44275/110592; b65 = 253/4096

    # 4th- and 5th-order weights
    c1 = 37/378;   c3 = 250/621;   c4 = 125/594;   c6 = 512/1771
    dc1 = c1 - 2825/27648
    dc3 = c3 - 18575/48384
    dc4 = c4 - 13525/55296
    dc5 = -277/14336
    dc6 = c6 - 1/4

    k1 = f(t, y)
    k2 = f(t + a2*h, v_add(y, v_scale(k1, b21*h)))
    k3 = f(t + a3*h, v_add(y, v_add(v_scale(k1, b31*h), v_scale(k2, b32*h))))
    k4 = f(t + a4*h, v_add(y, v_add(v_add(v_scale(k1, b41*h), v_scale(k2, b42*h)), v_scale(k3, b43*h))))
    k5 = f(t + a5*h, v_add(y, v_add(v_add(v_add(v_scale(k1, b51*h), v_scale(k2, b52*h)), v_scale(k3, b53*h)), v_scale(k4, b54*h))))
    k6 = f(t + a6*h, v_add(y, v_add(v_add(v_add(v_add(v_scale(k1, b61*h), v_scale(k2, b62*h)), v_scale(k3, b63*h)), v_scale(k4, b64*h)), v_scale(k5, b65*h))))

    # 4th order solution
    y4 = v_add(y, v_add(v_add(v_add(v_scale(k1, c1*h), v_scale(k3, c3*h)), v_scale(k4, c4*h)), v_scale(k6, c6*h)))

    # Error estimate (difference 5th - 4th)
    err = v_add(
        v_add(v_add(v_add(v_scale(k1, dc1*h), v_scale(k3, dc3*h)), v_scale(k4, dc4*h)), v_scale(k5, dc5*h)),
        v_scale(k6, dc6*h),
    )
    return y4, err

# ============================================================
# Public factory
# ============================================================

def make_integrator(cfg: Optional[IntegratorConfig] = None) -> Integrator:
    return Integrator(cfg or IntegratorConfig())

# ============================================================
# Example self-test (optional)
# ============================================================

if __name__ == "__main__":
    # Simple ballistic test with drag and damping
    sys = PhysicsSystem(dimension=3, gravity=[0.0, -9.81, 0.0])
    b = Body(id="ball", mass=1.0, pos=[0.0, 0.0, 0.0], vel=[10.0, 20.0, 0.0], drag=0.1, damping=0.0, max_speed=100.0)
    sys.add_body(b)

    # Example force provider: side wind on X after t>0.5
    def wind(t: float, system: PhysicsSystem, s: BodyState) -> Vec:
        return [5.0 if t > 0.5 else 0.0, 0.0, 0.0]
    sys.force_providers.append(wind)

    it = make_integrator(IntegratorConfig(name="rk45", adaptive=True, dt_max=1/60, tol_abs=1e-6, tol_rel=1e-4, speed_clamp=200.0))

    t = 0.0
    T = 2.0
    while t < T:
        dt = min(1/30, T - t)
        spent, st = it.step(sys, t, dt)
        t += spent

    print("final pos:", b.pos, "final vel:", b.vel)
    print("E_kin:", sys.kinetic_energy(), "E_pot:", sys.potential_energy_gravity())
