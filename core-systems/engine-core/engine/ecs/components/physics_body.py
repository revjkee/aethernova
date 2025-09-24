# engine-core/engine/ecs/components/physics_body.py
"""
Industrial-grade ECS PhysicsBody component (2D/3D).

Key features:
- 2D/3D support with shape primitives (SPHERE, BOX, CAPSULE, CONVEX[custom inertia])
- Body types: STATIC, KINEMATIC, DYNAMIC
- Mass & inertia from shape+density (override supported)
- Semi-implicit Euler integration with dt clamping and damping
- Force/impulse accumulation with world/local variants
- Sleep/wake logic with thresholds and timers
- CCD flags, gravity scale, material (friction, restitution)
- AABB computation (conservative)
- Dirty flags and version counter for cache invalidation
- Deterministic serialization/deserialization

No external deps. Math kept minimal for performance and clarity.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict, replace
from enum import Enum, IntFlag, auto
from typing import Dict, Iterable, List, Optional, Tuple, Union
import math

# -------------------------
# Small vector utilities
# -------------------------

Vec = Tuple[float, ...]  # 2 or 3 elements

def vdim(v: Vec) -> int: return len(v)
def vadd(a: Vec, b: Vec) -> Vec: return tuple(x + y for x, y in zip(a, b))
def vsub(a: Vec, b: Vec) -> Vec: return tuple(x - y for x, y in zip(a, b))
def vscale(a: Vec, s: float) -> Vec: return tuple(x * s for x in a)
def vdot(a: Vec, b: Vec) -> float: return sum(x * y for x, y in zip(a, b))
def vlen(a: Vec) -> float: return math.sqrt(vdot(a, a))
def vnorm(a: Vec, eps: float = 1e-12) -> Vec:
    l = vlen(a)
    return a if l < eps else vscale(a, 1.0 / l)
def vmax(a: Vec, b: Vec) -> Vec: return tuple(max(x, y) for x, y in zip(a, b))
def vmin(a: Vec, b: Vec) -> Vec: return tuple(min(x, y) for x, y in zip(a, b))
def vabs(a: Vec) -> Vec: return tuple(abs(x) for x in a)
def vzero(n: int) -> Vec: return tuple(0.0 for _ in range(n))

def cross2(a: Vec, b: Vec) -> float:
    # 2D scalar cross (ax*by - ay*bx)
    assert vdim(a) == 2 and vdim(b) == 2
    return a[0]*b[1] - a[1]*b[0]

def cross3(a: Vec, b: Vec) -> Vec:
    # 3D vector cross
    assert vdim(a) == 3 and vdim(b) == 3
    return (a[1]*b[2] - a[2]*b[1], a[2]*b[0] - a[0]*b[2], a[0]*b[1] - a[1]*b[0])

# -------------------------
# Enums & Flags
# -------------------------

class BodyType(Enum):
    STATIC = "static"
    KINEMATIC = "kinematic"
    DYNAMIC = "dynamic"

class ShapeType(Enum):
    SPHERE = "sphere"     # dim=3; for dim=2 treat as circle (use radius_x)
    BOX = "box"           # half extents
    CAPSULE = "capsule"   # radius + height (axis aligned to local Y for 3D, line for 2D)
    CONVEX = "convex"     # custom inertia supplied

class DirtyMask(IntFlag):
    NONE = 0
    TRANSFORM = auto()
    VELOCITY = auto()
    MASS = auto()
    MATERIAL = auto()
    ALL = TRANSFORM | VELOCITY | MASS | MATERIAL

# -------------------------
# Data classes
# -------------------------

@dataclass(slots=True)
class Material:
    friction: float = 0.8       # Coulomb friction coefficient
    restitution: float = 0.05   # bounciness [0..1]
    linear_damping: float = 0.04
    angular_damping: float = 0.04

    def clamp(self) -> None:
        self.friction = max(0.0, float(self.friction))
        self.restitution = min(1.0, max(0.0, float(self.restitution)))
        self.linear_damping = max(0.0, float(self.linear_damping))
        self.angular_damping = max(0.0, float(self.angular_damping))

@dataclass(slots=True)
class Shape:
    type: ShapeType
    # Parameters depend on type:
    # SPHERE: (radius,)
    # BOX: (hx, hy, [hz])
    # CAPSULE: (radius, height) - local Y is the axis (3D), in 2D along segment
    # CONVEX: supply 'inertia_override' or 'inertia_tensor' externally
    params: Tuple[float, ...]
    inertia_override: Optional[Tuple[float, ...]] = None  # scalar J (2D) or (Ixx,Iyy,Izz) (3D)
    com_offset: Optional[Vec] = None  # local center-of-mass offset, default zero

    def dim(self) -> int:
        # infer from params (BOX len=2 -> 2D, len=3 -> 3D). SPHERE: if params len==1 treat 3D.
        if self.type == ShapeType.BOX:
            return 2 if len(self.params) == 2 else 3
        if self.type == ShapeType.SPHERE:
            # treat sphere as 3D unless used in 2D body (caller ensures consistency)
            return 3
        if self.type == ShapeType.CAPSULE:
            return 3 if len(self.params) == 2 else 2
        return 3

# -------------------------
# PhysicsBody Component
# -------------------------

@dataclass(slots=True)
class PhysicsBody:
    # Identity
    entity_id: int
    version: int = 0

    # Kinematics/Transform (position + orientation)
    # 2D: position=(x,y), rotation=angle(rad)
    # 3D: position=(x,y,z), rotation=(qx,qy,qz,qw) unit quaternion
    position: Vec = field(default_factory=lambda: (0.0, 0.0))
    rotation: Tuple[float, ...] = field(default_factory=lambda: (0.0,))  # angle or quaternion

    # Velocities
    linear_velocity: Vec = field(default_factory=lambda: (0.0, 0.0))
    # 2D: angular=(w,), 3D: angular=(wx, wy, wz)
    angular_velocity: Tuple[float, ...] = field(default_factory=lambda: (0.0,))

    # Body & shape
    body_type: BodyType = BodyType.DYNAMIC
    shape: Shape = field(default_factory=lambda: Shape(ShapeType.BOX, (0.5, 0.5)))
    density: float = 1000.0  # kg/m^3 (or kg/m^2 in 2D interpretation)
    gravity_scale: float = 1.0

    # Mass & inertia (computed; can be overridden)
    mass: Optional[float] = None
    inv_mass: Optional[float] = None
    inertia: Optional[Tuple[float, ...]] = None   # 2D: (J,), 3D: (Ixx, Iyy, Izz)
    inv_inertia: Optional[Tuple[float, ...]] = None

    # Force/impulse accumulators
    force: Vec = field(default_factory=lambda: (0.0, 0.0))
    torque: Tuple[float, ...] = field(default_factory=lambda: (0.0,))

    # Damping/material
    material: Material = field(default_factory=Material)

    # Sleep/wake
    can_sleep: bool = True
    sleep_threshold_lin: float = 0.05
    sleep_threshold_ang: float = 0.05
    sleep_time: float = 0.0
    sleep_time_threshold: float = 0.5
    is_sleeping: bool = False

    # CCD & collision
    ccd: bool = False
    collision_enabled: bool = True
    collision_group: int = 0xFFFF
    collision_mask: int = 0xFFFF

    # Internal
    _dirty: DirtyMask = DirtyMask.ALL

    # ------------- Validation / Initialization -------------

    def __post_init__(self) -> None:
        self._validate_dimensions()
        self.material.clamp()
        if self.mass is None or self.inv_mass is None or self.inertia is None or self.inv_inertia is None:
            self._recompute_mass_inertia()
        self._dirty |= DirtyMask.ALL
        self.version += 1

    def _validate_dimensions(self) -> None:
        d = vdim(self.position)
        if d not in (2, 3):
            raise ValueError("position must be 2D or 3D")
        if d != vdim(self.linear_velocity):
            raise ValueError("linear_velocity dimension mismatch")
        if d == 2 and len(self.rotation) != 1:
            raise ValueError("2D rotation must be scalar angle")
        if d == 3 and len(self.rotation) != 4:
            raise ValueError("3D rotation must be quaternion (x,y,z,w)")
        if d == 2 and len(self.angular_velocity) != 1:
            raise ValueError("2D angular_velocity must be scalar")
        if d == 3 and len(self.angular_velocity) != 3:
            raise ValueError("3D angular_velocity must be vec3")
        # normalize quaternion
        if d == 3:
            qx, qy, qz, qw = self.rotation  # type: ignore
            norm = math.sqrt(qx*qx + qy*qy + qz*qz + qw*qw)
            if norm == 0:
                self.rotation = (0.0, 0.0, 0.0, 1.0)
            else:
                self.rotation = (qx/norm, qy/norm, qz/norm, qw/norm)

    # ------------- Mass & Inertia -------------

    def _recompute_mass_inertia(self) -> None:
        d = vdim(self.position)
        # STATIC has infinite mass/inertia; KINEMATIC by convention: infinite mass but controlled by velocity
        if self.body_type in (BodyType.STATIC, BodyType.KINEMATIC):
            self.mass = float("inf")
            self.inv_mass = 0.0
            if d == 2:
                self.inertia = (float("inf"),)
                self.inv_inertia = (0.0,)
            else:
                self.inertia = (float("inf"), float("inf"), float("inf"))
                self.inv_inertia = (0.0, 0.0, 0.0)
            return

        # DYNAMIC
        if self.shape.inertia_override is not None:
            # Use custom inertia (mass may still be computed from density if None)
            m = self._shape_mass(d)
            self.mass = m
            self.inv_mass = 0.0 if m == float("inf") or m == 0 else 1.0 / m
            if d == 2 and len(self.shape.inertia_override) == 1:
                J = max(1e-12, self.shape.inertia_override[0])
                self.inertia = (J,)
                self.inv_inertia = (1.0 / J,)
            elif d == 3 and len(self.shape.inertia_override) == 3:
                I = tuple(max(1e-12, x) for x in self.shape.inertia_override)
                self.inertia = I
                self.inv_inertia = tuple(1.0 / x for x in I)
            else:
                raise ValueError("inertia_override dimensionality mismatch")
            return

        # Compute from primitive shape
        m = self._shape_mass(d)
        self.mass = m
        self.inv_mass = 0.0 if m == float("inf") or m == 0 else 1.0 / m

        if d == 2:
            J = self._shape_inertia_2d(m)
            J = max(1e-12, J)
            self.inertia = (J,)
            self.inv_inertia = (1.0 / J,)
        else:
            Ixx, Iyy, Izz = self._shape_inertia_3d(m)
            Ixx, Iyy, Izz = (max(1e-12, Ixx), max(1e-12, Iyy), max(1e-12, Izz))
            self.inertia = (Ixx, Iyy, Izz)
            self.inv_inertia = (1.0 / Ixx, 1.0 / Iyy, 1.0 / Izz)

    def _shape_mass(self, d: int) -> float:
        rho = max(0.0, float(self.density))
        if self.shape.type == ShapeType.SPHERE:
            r = self.shape.params[0]
            if d == 2:
                # disk area * density (2D interpretation)
                area = math.pi * r * r
                return area * rho
            else:
                vol = (4.0/3.0) * math.pi * r**3
                return vol * rho
        elif self.shape.type == ShapeType.BOX:
            if d == 2:
                hx, hy = self.shape.params
                area = (2*hx) * (2*hy)
                return area * rho
            else:
                hx, hy, hz = self.shape.params
                vol = (2*hx) * (2*hy) * (2*hz)
                return vol * rho
        elif self.shape.type == ShapeType.CAPSULE:
            r, h = self.shape.params
            if d == 2:
                # rectangle + 2 semicircles (area)
                area = (2*r)*h + math.pi*r*r
                return area * rho
            else:
                # cylinder + 2 hemispheres (volume)
                vol = math.pi*r*r*h + (4.0/3.0)*math.pi*r**3
                return vol * rho
        elif self.shape.type == ShapeType.CONVEX:
            # require density*proxy_volume via params[0] (proxy volume/area)
            if not self.shape.params:
                raise ValueError("CONVEX shape requires params[0]=proxy_volume_or_area")
            proxy = max(0.0, self.shape.params[0])
            return proxy * rho
        else:
            raise ValueError("unknown shape")

    def _shape_inertia_2d(self, m: float) -> float:
        # About COM, for rotation around z (out of plane)
        if self.shape.type == ShapeType.SPHERE:
            r = self.shape.params[0]
            return 0.5 * m * r * r  # disk
        if self.shape.type == ShapeType.BOX:
            hx, hy = self.shape.params
            w, h = 2*hx, 2*hy
            return (m * (w*w + h*h)) / 12.0
        if self.shape.type == ShapeType.CAPSULE:
            r, h = self.shape.params
            # Approximation: rectangle + 2 semicircles inertia about COM
            rect = (m * ((2*r)**2 + h**2)) / 12.0 * 0.7
            ends = 0.3 * 0.5 * m * r * r
            return rect + ends
        if self.shape.type == ShapeType.CONVEX:
            if self.shape.inertia_override and len(self.shape.inertia_override) == 1:
                return self.shape.inertia_override[0]
            raise ValueError("CONVEX 2D requires inertia_override or specialized system")
        raise ValueError("unsupported shape in 2D inertia")

    def _shape_inertia_3d(self, m: float) -> Tuple[float, float, float]:
        if self.shape.type == ShapeType.SPHERE:
            r = self.shape.params[0]
            I = 0.4 * m * r * r
            return (I, I, I)
        if self.shape.type == ShapeType.BOX:
            hx, hy, hz = self.shape.params
            w, h, d = 2*hx, 2*hy, 2*hz
            return (
                (1/12) * m * (h*h + d*d),
                (1/12) * m * (w*w + d*d),
                (1/12) * m * (w*w + h*h),
            )
        if self.shape.type == ShapeType.CAPSULE:
            r, h = self.shape.params
            # Approximate inertia: cylinder + 2 hemispheres (around principal axes)
            cyl_Ix = cyl_Iy = (1/12)*m*(3*r*r + h*h)
            cyl_Iz = 0.5*m*r*r
            # Blend factors (approximate mass distribution)
            return (0.6*cyl_Ix, 0.6*cyl_Iy, 0.6*cyl_Iz)
        if self.shape.type == ShapeType.CONVEX:
            if self.shape.inertia_override and len(self.shape.inertia_override) == 3:
                return tuple(self.shape.inertia_override)  # type: ignore
            raise ValueError("CONVEX 3D requires inertia_override or specialized system")
        raise ValueError("unsupported shape in 3D inertia")

    # ------------- Forces & Impulses -------------

    def clear_forces(self) -> None:
        self.force = vzero(vdim(self.position))
        self.torque = (0.0,) if vdim(self.position) == 2 else (0.0, 0.0, 0.0)

    def apply_force_world(self, f: Vec, point_world: Optional[Vec] = None) -> None:
        """Apply continuous force in world space at point (world)."""
        if self.body_type != BodyType.DYNAMIC or self.is_sleeping:
            return
        d = vdim(self.position)
        if vdim(f) != d:
            raise ValueError("force dimension mismatch")
        self.force = vadd(self.force, f)
        if point_world is not None:
            if vdim(point_world) != d:
                raise ValueError("point dimension mismatch")
            r = vsub(point_world, self.position)  # lever arm
            self._apply_torque_from_lever(r, f)
        self._mark_dirty(DirtyMask.VELOCITY)

    def apply_impulse_world(self, j: Vec, point_world: Optional[Vec] = None) -> None:
        """Apply instantaneous impulse in world space at point (world)."""
        if self.body_type != BodyType.DYNAMIC:
            return
        d = vdim(self.position)
        if vdim(j) != d:
            raise ValueError("impulse dimension mismatch")
        # Linear impulse
        if self.inv_mass and self.inv_mass > 0:
            self.linear_velocity = vadd(self.linear_velocity, vscale(j, self.inv_mass))
        # Angular impulse
        if point_world is not None and self.inv_inertia is not None:
            r = vsub(point_world, self.position)
            self._apply_angular_impulse_from_lever(r, j)
        self._wake()
        self._mark_dirty(DirtyMask.VELOCITY)

    def _apply_torque_from_lever(self, r: Vec, f: Vec) -> None:
        d = vdim(self.position)
        if d == 2:
            tau = cross2(r, f)
            self.torque = (self.torque[0] + tau,)
        else:
            tau = cross3(r, f)
            self.torque = tuple(t + dt for t, dt in zip(self.torque, tau))  # type: ignore

    def _apply_angular_impulse_from_lever(self, r: Vec, j: Vec) -> None:
        d = vdim(self.position)
        if self.inv_inertia is None:
            return
        if d == 2:
            # torque impulse = r x j (scalar), w += tau * inv_inertia
            tau = cross2(r, j)
            self.angular_velocity = (self.angular_velocity[0] + tau * self.inv_inertia[0],)
        else:
            tau = cross3(r, j)
            self.angular_velocity = tuple(w + tau_i * inv_i for w, tau_i, inv_i in zip(self.angular_velocity, tau, self.inv_inertia))  # type: ignore

    # ------------- Integration -------------

    def integrate(self, dt: float, gravity: Vec = (0.0, -9.81, 0.0)) -> None:
        """Semi-implicit Euler with damping, sleep logic, and dt clamps."""
        if dt <= 0.0:
            return
        dt = min(dt, 1/15)  # clamp for stability

        d = vdim(self.position)
        g = gravity if vdim(gravity) == d else gravity[:d]

        if self.body_type == BodyType.DYNAMIC and not self.is_sleeping:
            # accelerations
            lin_acc = vscale(vadd(self.force, vscale(g, self.gravity_scale * (self.mass or 0.0))), self.inv_mass or 0.0)
            if d == 2:
                ang_acc = (self.torque[0] * (self.inv_inertia[0] if self.inv_inertia else 0.0),)
            else:
                ang_acc = tuple(t * inv for t, inv in zip(self.torque, self.inv_inertia or (0.0, 0.0, 0.0)))  # type: ignore

            # integrate velocities
            self.linear_velocity = vadd(self.linear_velocity, vscale(lin_acc, dt))
            if d == 2:
                self.angular_velocity = (self.angular_velocity[0] + ang_acc[0] * dt,)
            else:
                self.angular_velocity = tuple(w + a*dt for w, a in zip(self.angular_velocity, ang_acc))  # type: ignore

            # damping (exponential model)
            ld = max(0.0, self.material.linear_damping)
            ad = max(0.0, self.material.angular_damping)
            self.linear_velocity = vscale(self.linear_velocity, 1.0 / (1.0 + ld * dt))
            if d == 2:
                self.angular_velocity = (self.angular_velocity[0] / (1.0 + ad * dt),)
            else:
                self.angular_velocity = tuple(w / (1.0 + ad * dt) for w in self.angular_velocity)  # type: ignore

            # integrate transform
            self.position = vadd(self.position, vscale(self.linear_velocity, dt))
            self.rotation = self._integrate_orientation(self.rotation, self.angular_velocity, dt)

            # clear accumulators
            self.clear_forces()
            self._mark_dirty(DirtyMask.TRANSFORM | DirtyMask.VELOCITY)

            # sleep test
            self._update_sleep(dt)

        elif self.body_type == BodyType.KINEMATIC:
            # Kinematic follows velocity but ignores forces/mass
            self.position = vadd(self.position, vscale(self.linear_velocity, dt))
            self.rotation = self._integrate_orientation(self.rotation, self.angular_velocity, dt)
            self._mark_dirty(DirtyMask.TRANSFORM)

        # STATIC: nothing to do

    def _integrate_orientation(self, rot: Tuple[float, ...], av: Tuple[float, ...], dt: float) -> Tuple[float, ...]:
        d = len(rot)
        if d == 1:
            return (rot[0] + av[0]*dt,)
        else:
            # quaternion update by small-angle approximation
            wx, wy, wz = av
            half_dt = 0.5 * dt
            qx, qy, qz, qw = rot
            dq = (
                half_dt * ( wx*qw + wy*qz - wz*qy),
                half_dt * (-wx*qz + wy*qw + wz*qx),
                half_dt * ( wx*qy - wy*qx + wz*qw),
                -half_dt * ( wx*qx + wy*qy + wz*qz),
            )
            q_new = (qx + dq[0], qy + dq[1], qz + dq[2], qw + dq[3])
            # normalize
            n = math.sqrt(sum(c*c for c in q_new))
            if n == 0:
                return (0.0, 0.0, 0.0, 1.0)
            return tuple(c / n for c in q_new)  # type: ignore

    # ------------- Sleep / Wake -------------

    def _update_sleep(self, dt: float) -> None:
        if not self.can_sleep:
            self.sleep_time = 0.0
            self.is_sleeping = False
            return
        lv = vlen(self.linear_velocity)
        av = abs(self.angular_velocity[0]) if len(self.angular_velocity) == 1 else max(abs(a) for a in self.angular_velocity)
        if lv < self.sleep_threshold_lin and av < self.sleep_threshold_ang:
            self.sleep_time += dt
            if self.sleep_time >= self.sleep_time_threshold:
                self.is_sleeping = True
                self.linear_velocity = vzero(vdim(self.position))
                self.angular_velocity = (0.0,) if vdim(self.position) == 2 else (0.0, 0.0, 0.0)
        else:
            self._wake()

    def _wake(self) -> None:
        self.sleep_time = 0.0
        self.is_sleeping = False

    # ------------- Collision/AABB -------------

    def aabb(self) -> Tuple[Vec, Vec]:
        """
        Conservative world-space AABB ignoring rotation for BOX/CAPSULE (safe broad-phase).
        For engine with oriented bounds, replace by OBB transform with rotation.
        """
        d = vdim(self.position)
        p = self.position
        if self.shape.type == ShapeType.SPHERE:
            r = self.shape.params[0]
            ext = (r, r) if d == 2 else (r, r, r)
            return vsub(p, ext), vadd(p, ext)
        if self.shape.type == ShapeType.BOX:
            if d == 2:
                hx, hy = self.shape.params
                ext = (hx, hy)
            else:
                hx, hy, hz = self.shape.params
                ext = (hx, hy, hz)
            return vsub(p, ext), vadd(p, ext)
        if self.shape.type == ShapeType.CAPSULE:
            r, h = self.shape.params
            if d == 2:
                # line along local Y: radius expands on both axes
                ext = (r, r + 0.5*h)
            else:
                ext = (r, r + 0.5*h, r)
            return vsub(p, ext), vadd(p, ext)
        # CONVEX: require proxy half-extents in params[1..]
        if self.shape.type == ShapeType.CONVEX:
            if d == 2 and len(self.shape.params) >= 3:
                ext = (abs(self.shape.params[1]), abs(self.shape.params[2]))
            elif d == 3 and len(self.shape.params) >= 4:
                ext = (abs(self.shape.params[1]), abs(self.shape.params[2]), abs(self.shape.params[3]))
            else:
                # fallback minimal extents
                ext = (0.0, 0.0) if d == 2 else (0.0, 0.0, 0.0)
            return vsub(p, ext), vadd(p, ext)
        raise ValueError("unknown shape")

    # ------------- Dirty / Version -------------

    def _mark_dirty(self, mask: DirtyMask) -> None:
        self._dirty |= mask
        self.version += 1

    def consume_dirty(self) -> DirtyMask:
        d = self._dirty
        self._dirty = DirtyMask.NONE
        return d

    # ------------- Serialization -------------

    def to_dict(self) -> Dict:
        M = asdict(self)
        # dataclasses asdict expands deeply; ensure enums serialized as values
        M["body_type"] = self.body_type.value
        M["shape"]["type"] = self.shape.type.value
        M["_dirty"] = int(self._dirty)
        return M

    @staticmethod
    def from_dict(dct: Dict) -> "PhysicsBody":
        pb = PhysicsBody(
            entity_id=int(dct["entity_id"]),
            version=int(dct.get("version", 0)),
            position=tuple(dct.get("position", (0.0, 0.0))),  # type: ignore
            rotation=tuple(dct.get("rotation", (0.0,))),
            linear_velocity=tuple(dct.get("linear_velocity", (0.0, 0.0))),  # type: ignore
            angular_velocity=tuple(dct.get("angular_velocity", (0.0,))),
            body_type=BodyType(dct.get("body_type", "dynamic")),
            shape=Shape(ShapeType(dct["shape"]["type"]), tuple(dct["shape"]["params"]),
                        inertia_override=tuple(dct["shape"].get("inertia_override")) if dct["shape"].get("inertia_override") else None,
                        com_offset=tuple(dct["shape"].get("com_offset")) if dct["shape"].get("com_offset") else None),
            density=float(dct.get("density", 1000.0)),
            gravity_scale=float(dct.get("gravity_scale", 1.0)),
            mass=dct.get("mass"),
            inv_mass=dct.get("inv_mass"),
            inertia=tuple(dct["inertia"]) if dct.get("inertia") else None,
            inv_inertia=tuple(dct["inv_inertia"]) if dct.get("inv_inertia") else None,
            force=tuple(dct.get("force", (0.0, 0.0))),  # type: ignore
            torque=tuple(dct.get("torque", (0.0,))),
            material=Material(**dct.get("material", {})),
            can_sleep=bool(dct.get("can_sleep", True)),
            sleep_threshold_lin=float(dct.get("sleep_threshold_lin", 0.05)),
            sleep_threshold_ang=float(dct.get("sleep_threshold_ang", 0.05)),
            sleep_time=float(dct.get("sleep_time", 0.0)),
            sleep_time_threshold=float(dct.get("sleep_time_threshold", 0.5)),
            is_sleeping=bool(dct.get("is_sleeping", False)),
            ccd=bool(dct.get("ccd", False)),
            collision_enabled=bool(dct.get("collision_enabled", True)),
            collision_group=int(dct.get("collision_group", 0xFFFF)),
            collision_mask=int(dct.get("collision_mask", 0xFFFF)),
            _dirty=DirtyMask(dct.get("_dirty", int(DirtyMask.ALL))),
        )
        return pb

    # ------------- Utilities -------------

    def set_body_type(self, t: BodyType) -> None:
        if self.body_type != t:
            self.body_type = t
            self._recompute_mass_inertia()
            self._mark_dirty(DirtyMask.MASS)

    def set_shape(self, shape: Shape) -> None:
        self.shape = shape
        self._recompute_mass_inertia()
        self._mark_dirty(DirtyMask.MASS)

    def set_density(self, rho: float) -> None:
        self.density = max(0.0, float(rho))
        if self.body_type == BodyType.DYNAMIC:
            self._recompute_mass_inertia()
            self._mark_dirty(DirtyMask.MASS)

    def teleport(self, position: Vec, rotation: Tuple[float, ...]) -> None:
        self.position = tuple(float(x) for x in position)  # type: ignore
        self.rotation = tuple(float(x) for x in rotation)  # type: ignore
        self._wake()
        self._mark_dirty(DirtyMask.TRANSFORM)

    def set_velocity(self, linear: Vec, angular: Tuple[float, ...]) -> None:
        self.linear_velocity = tuple(float(x) for x in linear)  # type: ignore
        self.angular_velocity = tuple(float(x) for x in angular)
        self._wake()
        self._mark_dirty(DirtyMask.VELOCITY)

# -------------------------
# __all__
# -------------------------

__all__ = [
    "Vec",
    "BodyType",
    "ShapeType",
    "DirtyMask",
    "Material",
    "Shape",
    "PhysicsBody",
    # vec utils
    "vadd", "vsub", "vscale", "vdot", "vlen", "vnorm", "vabs",
]
