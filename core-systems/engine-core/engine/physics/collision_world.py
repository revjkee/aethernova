from __future__ import annotations

import math
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple, Union

# =========================
# Опциональные метрики
# =========================
_PROM = os.getenv("PHYS_PROMETHEUS", "false").lower() == "true"
_prom = None
if _PROM:
    try:
        from prometheus_client import Counter, Histogram, Gauge  # type: ignore

        class _Prom:
            def __init__(self):
                self.pairs = Gauge("phys_pairs", "Narrow-phase pairs tested", ["world"])
                self.contacts = Gauge("phys_contacts", "Contact count", ["world"])
                self.step = Histogram("phys_step_seconds", "Step wall time", ["world"], buckets=[0.0005,0.001,0.002,0.005,0.01,0.02,0.05])
                self.raycast = Counter("phys_raycast_total", "Raycasts", ["world"])
                self.ccd_clamps = Counter("phys_ccd_clamps_total", "CCD clamped moves", ["world"])
        _prom = _Prom()
    except Exception:
        _prom = None

# =========================
# Базовые типы и математика
# =========================

EPS = 1e-7
INF = float("inf")

Vec2 = Tuple[float, float]
Vec3 = Tuple[float, float, float]

def dot2(a: Vec2, b: Vec2) -> float:
    return a[0]*b[0] + a[1]*b[1]

def dot3(a: Vec3, b: Vec3) -> float:
    return a[0]*b[0] + a[1]*b[1] + a[2]*b[2]

def sub2(a: Vec2, b: Vec2) -> Vec2:
    return (a[0]-b[0], a[1]-b[1])

def add2(a: Vec2, b: Vec2) -> Vec2:
    return (a[0]+b[0], a[1]+b[1])

def mul2(a: Vec2, s: float) -> Vec2:
    return (a[0]*s, a[1]*s)

def length2(v: Vec2) -> float:
    return math.hypot(v[0], v[1])

def normalize2(v: Vec2) -> Vec2:
    l = length2(v)
    if l < EPS:
        return (1.0, 0.0)
    return (v[0]/l, v[1]/l)

def rot2(v: Vec2, c: float, s: float) -> Vec2:
    return (v[0]*c - v[1]*s, v[0]*s + v[1]*c)

def clamp01(x: float) -> float:
    return 0.0 if x < 0.0 else (1.0 if x > 1.0 else x)

# AABB 2D/3D
@dataclass(frozen=True)
class AABB2:
    min: Vec2
    max: Vec2

    def expand(self, m: float) -> "AABB2":
        return AABB2((self.min[0]-m, self.min[1]-m), (self.max[0]+m, self.max[1]+m))

    def overlaps(self, other: "AABB2") -> bool:
        return not (self.max[0] < other.min[0] or self.min[0] > other.max[0] or
                    self.max[1] < other.min[1] or self.min[1] > other.max[1])

    def ray_intersect(self, p: Vec2, d: Vec2, tmax: float = INF) -> Optional[float]:
        # slab method
        t0, t1 = 0.0, tmax
        for i in range(2):
            o = p[i]; di = d[i]; mn = self.min[i]; mx = self.max[i]
            if abs(di) < EPS:
                if o < mn or o > mx:
                    return None
            else:
                inv = 1.0/di
                tmin = (mn - o)*inv
                tmaxi = (mx - o)*inv
                if tmin > tmaxi:
                    tmin, tmaxi = tmaxi, tmin
                t0 = max(t0, tmin)
                t1 = min(t1, tmaxi)
                if t0 > t1:
                    return None
        return t0

@dataclass(frozen=True)
class AABB3:
    min: Vec3
    max: Vec3

    def expand(self, m: float) -> "AABB3":
        return AABB3((self.min[0]-m, self.min[1]-m, self.min[2]-m),
                     (self.max[0]+m, self.max[1]+m, self.max[2]+m))

    def overlaps(self, other: "AABB3") -> bool:
        return not (self.max[0] < other.min[0] or self.min[0] > other.max[0] or
                    self.max[1] < other.min[1] or self.min[1] > other.max[1] or
                    self.max[2] < other.min[2] or self.min[2] > other.max[2])

# =========================
# Фильтры столкновений
# =========================

@dataclass
class Filter:
    layer: int = 1         # битовая маска собственного слоя
    mask: int = 0xFFFFFFFF # какие слои принимаем
    group: int = 0         # групповой id (0 — нет)

    def can_collide(self, other: "Filter") -> bool:
        if self.group != 0 and self.group == other.group:
            return False  # пример: в одной группе не сталкиваемся
        return (self.layer & other.mask) != 0 and (other.layer & self.mask) != 0

# =========================
# Формы
# =========================

class ShapeKind:
    CIRCLE = "circle2"
    CAPSULE2 = "capsule2"
    OBB2 = "obb2"
    AABB2 = "aabb2"
    SPHERE = "sphere3"
    CAPSULE3 = "capsule3"
    AABB3 = "aabb3"

@dataclass
class Shape:
    kind: str

# 2D
@dataclass
class Circle(Shape):
    r: float
    def __init__(self, r: float): super().__init__(ShapeKind.CIRCLE); self.r = float(r)

@dataclass
class Capsule2(Shape):
    half: float
    radius: float
    def __init__(self, half: float, radius: float): super().__init__(ShapeKind.CAPSULE2); self.half = float(half); self.radius = float(radius)

@dataclass
class OBB2(Shape):
    hx: float
    hy: float
    def __init__(self, hx: float, hy: float): super().__init__(ShapeKind.OBB2); self.hx = float(hx); self.hy = float(hy)

@dataclass
class Box2(Shape):
    hx: float
    hy: float
    def __init__(self, hx: float, hy: float): super().__init__(ShapeKind.AABB2); self.hx = float(hx); self.hy = float(hy)

# 3D
@dataclass
class Sphere(Shape):
    r: float
    def __init__(self, r: float): super().__init__(ShapeKind.SPHERE); self.r = float(r)

@dataclass
class Capsule3(Shape):
    half: float
    radius: float
    def __init__(self, half: float, radius: float): super().__init__(ShapeKind.CAPSULE3); self.half = float(half); self.radius = float(radius)

@dataclass
class Box3(Shape):
    hx: float
    hy: float
    hz: float
    def __init__(self, hx: float, hy: float, hz: float): super().__init__(ShapeKind.AABB3); self.hx = float(hx); self.hy = float(hy); self.hz = float(hz)

# =========================
# Трансформы
# =========================

@dataclass
class Transform2:
    p: Vec2
    rot: float = 0.0  # radians

    def basis(self) -> Tuple[float, float]:
        c = math.cos(self.rot); s = math.sin(self.rot)
        return c, s

@dataclass
class Transform3:
    p: Vec3  # без вращения (для упрощения; AABB/Sphere/Capsule инвариантны к вращению в 3D здесь)
    # Для OBB3 потребовалась бы матрица/кватернион.

# =========================
# Тело (коллайдер)
# =========================

BodyId = int

@dataclass
class Body:
    id: BodyId
    shape: Shape
    tf2: Optional[Transform2] = None
    tf3: Optional[Transform3] = None
    dynamic: bool = True
    filter: Filter = field(default_factory=Filter)
    user: Any = None
    ccd: bool = False
    velocity2: Vec2 = (0.0, 0.0)
    velocity3: Vec3 = (0.0, 0.0, 0.0)
    margin: float = 0.01  # «толстый» AABB padding

# =========================
# Маникфолд контакта
# =========================

@dataclass
class ContactPoint:
    position: Union[Vec2, Vec3]
    penetration: float

@dataclass
class Manifold:
    a: BodyId
    b: BodyId
    normal: Union[Vec2, Vec3]
    depth: float
    points: List[ContactPoint] = field(default_factory=list)

# =========================
# Uniform Grid (broad-phase)
# =========================

Cell = Tuple[int, int, int]  # z=0 для 2D

def _cell_coords_2(aabb: AABB2, inv: float) -> Tuple[int,int,int,int]:
    x0 = math.floor(aabb.min[0]*inv); y0 = math.floor(aabb.min[1]*inv)
    x1 = math.floor(aabb.max[0]*inv); y1 = math.floor(aabb.max[1]*inv)
    return x0, y0, x1, y1

def _cell_coords_3(aabb: AABB3, inv: float) -> Tuple[int,int,int,int,int,int]:
    x0 = math.floor(aabb.min[0]*inv); y0 = math.floor(aabb.min[1]*inv); z0 = math.floor(aabb.min[2]*inv)
    x1 = math.floor(aabb.max[0]*inv); y1 = math.floor(aabb.max[1]*inv); z1 = math.floor(aabb.max[2]*inv)
    return x0,y0,z0,x1,y1,z1

# =========================
# Узкая фаза — вспомогательные AABB
# =========================

def body_aabb2(b: Body) -> AABB2:
    assert b.tf2 is not None
    p = b.tf2.p
    m = b.margin
    if b.shape.kind == ShapeKind.CIRCLE:
        r = b.shape.r
        return AABB2((p[0]-r-m, p[1]-r-m), (p[0]+r+m, p[1]+r+m))
    if b.shape.kind == ShapeKind.CAPSULE2:
        c, s = b.tf2.basis()
        axis = (c, s)
        half = b.shape.half; r = b.shape.radius
        # капсула: отрезок [-half, +half] по оси + радиус
        # max extent = half along axis + r perpendicularly
        # оценим AABB консервативно
        ex = abs(axis[0])*half + r; ey = abs(axis[1])*half + r
        return AABB2((p[0]-ex-m, p[1]-ey-m), (p[0]+ex+m, p[1]+ey+m))
    if b.shape.kind == ShapeKind.OBB2:
        c, s = b.tf2.basis()
        hx, hy = b.shape.hx, b.shape.hy
        # экстенты OBB -> AABB
        ex = abs(c)*hx + abs(s)*hy
        ey = abs(s)*hx + abs(c)*hy
        return AABB2((p[0]-ex-m, p[1]-ey-m), (p[0]+ex+m, p[1]+ey+m))
    if b.shape.kind == ShapeKind.AABB2:
        hx, hy = b.shape.hx, b.shape.hy
        return AABB2((p[0]-hx-m, p[1]-hy-m), (p[0]+hx+m, p[1]+hy+m))
    raise ValueError("Unsupported 2D shape")

def body_aabb3(b: Body) -> AABB3:
    assert b.tf3 is not None
    p = b.tf3.p; m = b.margin
    if b.shape.kind == ShapeKind.SPHERE:
        r = b.shape.r
        return AABB3((p[0]-r-m, p[1]-r-m, p[2]-r-m), (p[0]+r+m, p[1]+r+m, p[2]+r+m))
    if b.shape.kind == ShapeKind.CAPSULE3:
        half = b.shape.half; r = b.shape.radius
        # ось капсулы фиксируем вдоль Y (для упрощения; при необходимости — добавьте ориентацию)
        return AABB3((p[0]-r-m, p[1]-half-r-m, p[2]-r-m), (p[0]+r+m, p[1]+half+r+m, p[2]+r+m))
    if b.shape.kind == ShapeKind.AABB3:
        hx, hy, hz = b.shape.hx, b.shape.hy, b.shape.hz
        return AABB3((p[0]-hx-m, p[1]-hy-m, p[2]-hz-m), (p[0]+hx+m, p[1]+hy+m, p[2]+hz+m))
    raise ValueError("Unsupported 3D shape")

# =========================
# Тесты узкой фазы (2D)
# =========================

def circle_circle(pa: Vec2, ra: float, pb: Vec2, rb: float) -> Optional[Manifold]:
    d = sub2(pb, pa); dist = length2(d); r = ra + rb
    if dist > r + EPS: return None
    if dist < EPS:  # совпадение центра — выбираем произвольную нормаль
        n = (1.0, 0.0); depth = r
        cp = add2(pa, mul2(n, ra))
        return "m", n, depth, [cp]
    n = (d[0]/(dist+EPS), d[1]/(dist+EPS))
    depth = r - dist
    cp = add2(pa, mul2(n, ra))
    return "m", n, depth, [cp]

def circle_obb(pa: Vec2, ra: float, pb: Vec2, c: float, s: float, hx: float, hy: float) -> Optional[Tuple[str,Vec2,float,List[Vec2]]]:
    # в локальных координатах OBB
    rel = sub2(pa, pb)
    local = ( rel[0]*c + rel[1]*s, -rel[0]*s + rel[1]*c )
    clamped = (max(-hx, min(hx, local[0])), max(-hy, min(hy, local[1])))
    diff = (local[0]-clamped[0], local[1]-clamped[1])
    d2 = diff[0]*diff[0] + diff[1]*diff[1]
    if d2 > (ra+EPS)*(ra+EPS): return None
    # мировая нормаль
    n_local = normalize2(diff) if d2 > EPS else (1.0, 0.0)
    n_world = ( n_local[0]*c - n_local[1]*s, n_local[0]*s + n_local[1]*c )
    closest_world = ( pb[0] + clamped[0]*c - clamped[1]*s, pb[1] + clamped[0]*s + clamped[1]*c )
    depth = ra - math.sqrt(max(d2, 0.0))
    cp = closest_world
    return "m", n_world, depth, [cp]

def obb_obb(pa: Vec2, ca: float, sa: float, hxa: float, hya: float,
            pb: Vec2, cb: float, sb: float, hxb: float, hyb: float) -> Optional[Tuple[str,Vec2,float,List[Vec2]]]:
    # SAT для 2D OBB: 4 оси (2 собственные + 2 чужие)
    axes = [(ca, sa), (-sa, ca), (cb, sb), (-sb, cb)]  # eX_a, eY_a, eX_b, eY_b
    best_overlap = INF; best_axis: Optional[Vec2] = None
    to_b = sub2(pb, pa)
    for i, (cx, sx) in enumerate(axes):
        axis = (cx, sx)
        # проекция разности центров
        dist = abs(to_b[0]*axis[0] + to_b[1]*axis[1])
        # проекции половин
        ra = abs(hxa*axis[0]*ca + hya*axis[1]*(-sa)) + abs(hxa*axis[0]*sa + hya*axis[1]*ca)  # |A| на axis
        rb = abs(hxb*axis[0]*cb + hyb*axis[1]*(-sb)) + abs(hxb*axis[0]*sb + hyb*axis[1]*cb)
        overlap = ra + rb - dist
        if overlap < 0.0:
            return None
        if overlap < best_overlap:
            best_overlap = overlap
            best_axis = axis
    n = best_axis if best_axis else (1.0,0.0)
    # направление нормали от A к B
    if dot2(n, to_b) < 0: n = (-n[0], -n[1])
    # контактные точки (упрощенно — центр поверхности A)
    cp = add2(pa, mul2(n, min(hxa, hya)))
    return "m", n, best_overlap, [cp]

# =========================
# Узкая фаза (3D упрощенная)
# =========================

def sphere_sphere(pa: Vec3, ra: float, pb: Vec3, rb: float) -> Optional[Manifold]:
    d = (pb[0]-pa[0], pb[1]-pa[1], pb[2]-pa[2])
    dist2 = d[0]*d[0]+d[1]*d[1]+d[2]*d[2]; r = ra+rb
    if dist2 > (r+EPS)*(r+EPS): return None
    dist = math.sqrt(max(dist2, 0.0))
    if dist < EPS:
        n = (1.0,0.0,0.0); depth = r
        cp = (pa[0]+n[0]*ra, pa[1]+n[1]*ra, pa[2]+n[2]*ra)
        return Manifold(0,0,n,depth,[ContactPoint(cp, depth)])
    n = (d[0]/(dist+EPS), d[1]/(dist+EPS), d[2]/(dist+EPS))
    depth = r - dist
    cp = (pa[0]+n[0]*ra, pa[1]+n[1]*ra, pa[2]+n[2]*ra)
    return Manifold(0,0,n,depth,[ContactPoint(cp, depth)])

# =========================
# Колбэки событий
# =========================
BeginCB = Callable[[Manifold], None]
PersistCB = Callable[[Manifold], None]
EndCB = Callable[[BodyId, BodyId], None]

# =========================
# Мир столкновений
# =========================

class CollisionWorld:
    """
    Универсальный мир столкновений (2D/3D) с быстрым broad-phase на Uniform Grid,
    фильтрами слоёв/масок, узкой фазой (набор форм) и CCD через swept AABB.
    """
    def __init__(self, name: str = "world", cell_size: float = 1.0) -> None:
        self.name = name
        self.cell = max(1e-3, float(cell_size))
        self.inv_cell = 1.0/self.cell
        self._bodies: Dict[BodyId, Body] = {}
        self._cells: Dict[Cell, Set[BodyId]] = {}
        self._aabbs2: Dict[BodyId, AABB2] = {}
        self._aabbs3: Dict[BodyId, AABB3] = {}
        self._next_id: int = 1
        self.on_begin: Optional[BeginCB] = None
        self.on_persist: Optional[PersistCB] = None
        self.on_end: Optional[EndCB] = None
        self._contacts_prev: Set[Tuple[int,int]] = set()
        self._contacts_now: Set[Tuple[int,int]] = set()

    # --------- API тел ---------

    def add_body(self, shape: Shape, tf: Union[Transform2, Transform3], *, dynamic: bool = True,
                 filter: Optional[Filter] = None, user: Any = None, ccd: bool = False, margin: float = 0.01) -> BodyId:
        bid = self._next_id; self._next_id += 1
        b = Body(bid, shape, tf2=tf if isinstance(tf, Transform2) else None,
                 tf3=tf if isinstance(tf, Transform3) else None,
                 dynamic=dynamic, filter=filter or Filter(), user=user, ccd=ccd, margin=margin)
        self._bodies[bid] = b
        self._insert(b)
        return bid

    def remove_body(self, bid: BodyId) -> None:
        b = self._bodies.pop(bid, None)
        if not b: return
        self._erase(bid)
        self._aabbs2.pop(bid, None); self._aabbs3.pop(bid, None)

    def get(self, bid: BodyId) -> Optional[Body]:
        return self._bodies.get(bid)

    # --------- Перемещение ---------

    def set_transform(self, bid: BodyId, tf: Union[Transform2, Transform3]) -> None:
        b = self._bodies[bid]
        if isinstance(tf, Transform2):
            b.tf2 = tf
        else:
            b.tf3 = tf
        self._update_cells(b)

    def set_velocity2(self, bid: BodyId, v: Vec2) -> None:
        b = self._bodies[bid]; b.velocity2 = v

    def set_velocity3(self, bid: BodyId, v: Vec3) -> None:
        b = self._bodies[bid]; b.velocity3 = v

    # --------- Шаг симуляции ---------

    def step(self, dt: float) -> None:
        t0 = time.perf_counter()
        self._contacts_now.clear()

        # 1) Интеграция + CCD (только динамические)
        for b in self._bodies.values():
            if not b.dynamic:
                continue
            if b.tf2:
                self._move2_ccd(b, dt)
            elif b.tf3:
                self._move3_ccd(b, dt)
            self._update_cells(b)

        # 2) Broad-phase: кандидаты
        pairs = self._gather_pairs()

        # 3) Narrow-phase
        manifolds: List[Manifold] = []
        for a_id, b_id in pairs:
            a = self._bodies.get(a_id); b = self._bodies.get(b_id)
            if not a or not b: continue
            if not a.filter.can_collide(b.filter): continue
            m = self._narrow(a, b)
            if m is None: continue
            m.a, m.b = a_id, b_id
            manifolds.append(m)
            key = (min(a_id,b_id), max(a_id,b_id))
            self._contacts_now.add(key)

        # 4) События
        if self.on_begin or self.on_persist or self.on_end:
            prev = self._contacts_prev
            now = self._contacts_now
            ended = prev - now
            started = now - prev
            # begin/persist
            for m in manifolds:
                key = (min(m.a, m.b), max(m.a, m.b))
                if key in started:
                    if self.on_begin: self.on_begin(m)
                else:
                    if self.on_persist: self.on_persist(m)
            # end
            if self.on_end:
                for k in ended:
                    self.on_end(k[0], k[1])
            self._contacts_prev = now.copy()

        if _prom:
            try:
                _prom.pairs.labels(self.name).set(len(pairs))
                _prom.contacts.labels(self.name).set(len(self._contacts_now))
                _prom.step.labels(self.name).observe(max(0.0, time.perf_counter()-t0))
            except Exception:
                pass

    # --------- Запросы ---------

    def raycast2(self, p: Vec2, d: Vec2, tmax: float = INF, mask: int = 0xFFFFFFFF) -> Optional[Tuple[BodyId,float,Vec2]]:
        if _prom: 
            try: _prom.raycast.labels(self.name).inc()
            except Exception: pass
        best_t = tmax; best: Optional[Tuple[int,float,Vec2]] = None
        # грубая фильтрация по AABB
        # пройдём по ячейкам луча дискретно: шаг с размером ячейки
        step_len = self.cell / (length2(d)+EPS)
        t = 0.0
        seen: Set[int] = set()
        while t <= tmax + EPS:
            pt = (p[0]+d[0]*t, p[1]+d[1]*t)
            cell = (math.floor(pt[0]*self.inv_cell), math.floor(pt[1]*self.inv_cell), 0)
            for bid in self._cells.get(cell, ()):
                if bid in seen: continue
                seen.add(bid)
                b = self._bodies[bid]
                if (b.filter.layer & mask) == 0: continue
                aabb = self._aabbs2.get(bid)
                if not aabb: continue
                thit = aabb.ray_intersect(p, d, best_t)
                if thit is not None and thit < best_t:
                    best_t = thit
                    n = normalize2(d)  # нормаль луча как направление — для API вернём точку
                    hitp = (p[0]+d[0]*best_t, p[1]+d[1]*best_t)
                    best = (bid, best_t, hitp)
            t += step_len
        return best

    def overlap_aabb2(self, query: AABB2, mask: int = 0xFFFFFFFF) -> List[BodyId]:
        x0,y0,x1,y1 = _cell_coords_2(query, self.inv_cell)
        out: Set[int] = set()
        for x in range(x0, x1+1):
            for y in range(y0, y1+1):
                for bid in self._cells.get((x,y,0), ()):
                    if bid in out: continue
                    b = self._bodies[bid]
                    if (b.filter.layer & mask) == 0: continue
                    aabb = self._aabbs2.get(bid)
                    if aabb and aabb.overlaps(query):
                        out.add(bid)
        return sorted(out)

    # --------- Внутреннее: CCD ---------

    def _move2_ccd(self, b: Body, dt: float) -> None:
        v = b.velocity2
        if abs(v[0])+abs(v[1]) < EPS or not b.ccd:
            tf = Transform2((b.tf2.p[0]+v[0]*dt, b.tf2.p[1]+v[1]*dt), b.tf2.rot)
            b.tf2 = tf
            return
        # swept AABB: текущий AABB и целевой, объединённый
        a0 = body_aabb2(b)
        target = Transform2((b.tf2.p[0]+v[0]*dt, b.tf2.p[1]+v[1]*dt), b.tf2.rot)
        pdir = normalize2(v)
        swept = AABB2((min(a0.min[0], a0.min[0]+v[0]*dt), min(a0.min[1], a0.min[1]+v[1]*dt)),
                      (max(a0.max[0], a0.max[0]+v[0]*dt), max(a0.max[1], a0.max[1]+v[1]*dt)))
        # кандидаты по swept‑AABB
        cands = self.overlap_aabb2(swept, mask=b.filter.mask)
        toi = 1.0
        hit = False
        for cid in cands:
            if cid == b.id: continue
            other = self._bodies[cid]
            if not b.filter.can_collide(other.filter): continue
            aabb = self._aabbs2.get(cid)
            if not aabb: continue
            t = aabb.ray_intersect(b.tf2.p, mul2(pdir, length2(v)*dt), tmax=length2(v)*dt)
            if t is not None:
                toi = min(toi, t/(length2(v)*dt+EPS)); hit = True
        if hit:
            newp = (b.tf2.p[0]+v[0]*toi*dt, b.tf2.p[1]+v[1]*toi*dt)
            if _prom:
                try: _prom.ccd_clamps.labels(self.name).inc()
                except Exception: pass
        else:
            newp = target.p
        b.tf2 = Transform2(newp, b.tf2.rot)

    def _move3_ccd(self, b: Body, dt: float) -> None:
        # упрощённое перемещение без raycast‑шага (оставлено как TODO для 3D)
        v = b.velocity3
        if abs(v[0])+abs(v[1])+abs(v[2]) < EPS or not b.ccd:
            tf = Transform3((b.tf3.p[0]+v[0]*dt, b.tf3.p[1]+v[1]*dt, b.tf3.p[2]+v[2]*dt))
            b.tf3 = tf
            return
        tf = Transform3((b.tf3.p[0]+v[0]*dt, b.tf3.p[1]+v[1]*dt, b.tf3.p[2]+v[2]*dt))
        b.tf3 = tf  # при необходимости добавьте swept‑AABB по аналогии с 2D

    # --------- Внутреннее: Broad Phase ---------

    def _insert(self, b: Body) -> None:
        if b.tf2:
            a = body_aabb2(b); self._aabbs2[b.id] = a
            x0,y0,x1,y1 = _cell_coords_2(a, self.inv_cell)
            for x in range(x0,x1+1):
                for y in range(y0,y1+1):
                    self._cells.setdefault((x,y,0), set()).add(b.id)
        else:
            a = body_aabb3(b); self._aabbs3[b.id] = a
            x0,y0,z0,x1,y1,z1 = _cell_coords_3(a, self.inv_cell)
            for x in range(x0,x1+1):
                for y in range(y0,y1+1):
                    for z in range(z0,z1+1):
                        self._cells.setdefault((x,y,z), set()).add(b.id)

    def _erase(self, bid: BodyId) -> None:
        # удалить из всех ячеек
        for cell, s in list(self._cells.items()):
            if bid in s:
                s.remove(bid)
                if not s:
                    self._cells.pop(cell, None)

    def _update_cells(self, b: Body) -> None:
        # простая стратегия: удалить/вставить (можно оптимизировать трекингом предыдущих cell bounds)
        self._erase(b.id)
        self._insert(b)

    def _gather_pairs(self) -> List[Tuple[int,int]]:
        # для каждой ячейки все пары (i<j) — кандидаты
        pairs: Set[Tuple[int,int]] = set()
        for ids in self._cells.values():
            arr = sorted(ids)
            n = len(arr)
            for i in range(n):
                bi = arr[i]
                ai2 = self._aabbs2.get(bi); ai3 = self._aabbs3.get(bi)
                for j in range(i+1, n):
                    bj = arr[j]
                    # грубый AABB‑тест
                    aj2 = self._aabbs2.get(bj); aj3 = self._aabbs3.get(bj)
                    if ai2 and aj2:
                        if ai2.overlaps(aj2):
                            pairs.add((bi,bj))
                    elif ai3 and aj3:
                        if ai3.overlaps(aj3):
                            pairs.add((bi,bj))
        return sorted(pairs)

    # --------- Внутреннее: Narrow Phase ---------

    def _narrow(self, a: Body, b: Body) -> Optional[Manifold]:
        # 2D
        if a.tf2 and b.tf2:
            pa = a.tf2.p; pb = b.tf2.p
            if a.shape.kind == ShapeKind.CIRCLE and b.shape.kind == ShapeKind.CIRCLE:
                r = circle_circle(pa, a.shape.r, pb, b.shape.r)
                if r is None: return None
                _, n, depth, pts = r
                return Manifold(a.id, b.id, n, depth, [ContactPoint(pts[0], depth)])
            if a.shape.kind == ShapeKind.CIRCLE and b.shape.kind == ShapeKind.OBB2:
                c, s = b.tf2.basis()
                r = circle_obb(pa, a.shape.r, pb, c, s, b.shape.hx, b.shape.hy)
                if r is None: return None
                _, n, depth, pts = r
                return Manifold(a.id, b.id, n, depth, [ContactPoint(pts[0], depth)])
            if b.shape.kind == ShapeKind.CIRCLE and a.shape.kind == ShapeKind.OBB2:
                c, s = a.tf2.basis()
                r = circle_obb(pb, b.shape.r, pa, c, s, a.shape.hx, a.shape.hy)
                if r is None: return None
                _, n, depth, pts = r
                n = (-n[0], -n[1])
                return Manifold(a.id, b.id, n, depth, [ContactPoint(pts[0], depth)])
            if a.shape.kind == ShapeKind.OBB2 and b.shape.kind == ShapeKind.OBB2:
                ca, sa = a.tf2.basis(); cb, sb = b.tf2.basis()
                r = obb_obb(pa, ca, sa, a.shape.hx, a.shape.hy, pb, cb, sb, b.shape.hx, b.shape.hy)
                if r is None: return None
                _, n, depth, pts = r
                return Manifold(a.id, b.id, n, depth, [ContactPoint(pts[0], depth)])
            # AABB2 быстрый тест
            if a.shape.kind == ShapeKind.AABB2 and b.shape.kind == ShapeKind.AABB2:
                aa = body_aabb2(a); bb = body_aabb2(b)
                if not aa.overlaps(bb): return None
                # нормаль — ось наименьшей пенетрации
                dx = min(aa.max[0]-bb.min[0], bb.max[0]-aa.min[0])
                dy = min(aa.max[1]-bb.min[1], bb.max[1]-aa.min[1])
                if dx < dy:
                    n = (1.0,0.0) if aa.max[0] > bb.min[0] else (-1.0,0.0)
                    depth = dx
                else:
                    n = (0.0,1.0) if aa.max[1] > bb.min[1] else (0.0,-1.0)
                    depth = dy
                cp = ((max(aa.min[0], bb.min[0])+min(aa.max[0], bb.max[0]))*0.5,
                      (max(aa.min[1], bb.min[1])+min(aa.max[1], bb.max[1]))*0.5)
                return Manifold(a.id, b.id, n, depth, [ContactPoint(cp, depth)])
            # Прочие пары 2D можно добавить по мере необходимости (капсулы и т.д.)
            return None

        # 3D (упрощённо)
        if a.tf3 and b.tf3:
            pa = a.tf3.p; pb = b.tf3.p
            if a.shape.kind == ShapeKind.SPHERE and b.shape.kind == ShapeKind.SPHERE:
                m = sphere_sphere(pa, a.shape.r, pb, b.shape.r)
                return m
            if a.shape.kind == ShapeKind.AABB3 and b.shape.kind == ShapeKind.AABB3:
                aa = body_aabb3(a); bb = body_aabb3(b)
                if not aa.overlaps(bb): return None
                # грубая нормаль по оси наименьшего проникновения
                dx = min(aa.max[0]-bb.min[0], bb.max[0]-aa.min[0])
                dy = min(aa.max[1]-bb.min[1], bb.max[1]-aa.min[1])
                dz = min(aa.max[2]-bb.min[2], bb.max[2]-aa.min[2])
                if dx <= dy and dx <= dz: n = (1.0,0.0,0.0); depth=dx
                elif dy <= dx and dy <= dz: n = (0.0,1.0,0.0); depth=dy
                else: n = (0.0,0.0,1.0); depth=dz
                cp = ((max(aa.min[0], bb.min[0])+min(aa.max[0], bb.max[0]))*0.5,
                      (max(aa.min[1], bb.min[1])+min(aa.max[1], bb.max[1]))*0.5,
                      (max(aa.min[2], bb.min[2])+min(aa.max[2], bb.max[2]))*0.5)
                return Manifold(a.id, b.id, n, depth, [ContactPoint(cp, depth)])
            return None

        return None
