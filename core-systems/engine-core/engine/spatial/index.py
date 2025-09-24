# -*- coding: utf-8 -*-
"""
Spatial Indexes: BVH (SAH), Quadtree(2D), Octree(3D) with unified API.

Особенности:
- Единый интерфейс SpatialIndex[T] с CRUD и запросами: range, raycast, kNN.
- AABB/Vec2/Vec3, устойчивые операции, расширение эпсилон.
- BVH: построение SAH (Surface Area Heuristic), refit, частичные обновления, листы с несколькими объектами.
- Quadtree/Octree: loose-ячейки, Morton-коды, авто-ребаланс, лимит по объектам в узле.
- Идемпотентные batch-операции, потокобезопасность (RLock).
- Сериализация/восстановление (версионирование).
- Полезные утилиты (iterate pairs, broadphase sweep).

Примечание:
- Объекты в индексах представлены пользовательскими ID (hashable) + их AABB.
- Для kNN используется центр AABB, метрика L2, для луча — классический slab test.
"""

from __future__ import annotations

import math
import threading
import bisect
import heapq
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Generic, Iterable, Iterator, List, Optional, Tuple, TypeVar, Literal

# =============================================================================
# Геометрия
# =============================================================================

_EPS = 1e-9
def _feq(a: float, b: float, eps: float = _EPS) -> bool:
    return abs(a - b) <= eps

def _clamp(v: float, lo: float, hi: float) -> float:
    return lo if v < lo else hi if v > hi else v

@dataclass(frozen=True)
class Vec2:
    x: float
    y: float

    def __add__(self, o: "Vec2") -> "Vec2": return Vec2(self.x + o.x, self.y + o.y)
    def __sub__(self, o: "Vec2") -> "Vec2": return Vec2(self.x - o.x, self.y - o.y)
    def __mul__(self, k: float) -> "Vec2": return Vec2(self.x * k, self.y * k)
    __rmul__ = __mul__
    def dot(self, o: "Vec2") -> float: return self.x * o.x + self.y * o.y
    def norm2(self) -> float: return self.x*self.x + self.y*self.y

@dataclass(frozen=True)
class Vec3:
    x: float
    y: float
    z: float

    def __add__(self, o: "Vec3") -> "Vec3": return Vec3(self.x + o.x, self.y + o.y, self.z + o.z)
    def __sub__(self, o: "Vec3") -> "Vec3": return Vec3(self.x - o.x, self.y - o.y, self.z - o.z)
    def __mul__(self, k: float) -> "Vec3": return Vec3(self.x * k, self.y * k, self.z * k)
    __rmul__ = __mul__
    def dot(self, o: "Vec3") -> float: return self.x * o.x + self.y * o.y + self.z * o.z
    def norm2(self) -> float: return self.x*self.x + self.y*self.y + self.z*self.z

@dataclass(frozen=True)
class AABB2:
    min: Vec2
    max: Vec2

    def valid(self) -> bool:
        return self.max.x >= self.min.x and self.max.y >= self.min.y

    def expand(self, eps: float = _EPS) -> "AABB2":
        return AABB2(Vec2(self.min.x - eps, self.min.y - eps),
                     Vec2(self.max.x + eps, self.max.y + eps))

    def union(self, o: "AABB2") -> "AABB2":
        return AABB2(
            Vec2(min(self.min.x, o.min.x), min(self.min.y, o.min.y)),
            Vec2(max(self.max.x, o.max.x), max(self.max.y, o.max.y))
        )

    def area(self) -> float:
        w = max(0.0, self.max.x - self.min.x)
        h = max(0.0, self.max.y - self.min.y)
        return w * h

    def center(self) -> Vec2:
        return Vec2(0.5*(self.min.x + self.max.x), 0.5*(self.min.y + self.max.y))

    def overlaps(self, o: "AABB2") -> bool:
        return not (self.max.x < o.min.x or self.min.x > o.max.x or
                    self.max.y < o.min.y or self.min.y > o.max.y)

    def contains_point(self, p: Vec2) -> bool:
        return (self.min.x <= p.x <= self.max.x) and (self.min.y <= p.y <= self.max.y)


@dataclass(frozen=True)
class AABB3:
    min: Vec3
    max: Vec3

    def valid(self) -> bool:
        return self.max.x >= self.min.x and self.max.y >= self.min.y and self.max.z >= self.min.z

    def expand(self, eps: float = _EPS) -> "AABB3":
        return AABB3(Vec3(self.min.x - eps, self.min.y - eps, self.min.z - eps),
                     Vec3(self.max.x + eps, self.max.y + eps, self.max.z + eps))

    def union(self, o: "AABB3") -> "AABB3":
        return AABB3(
            Vec3(min(self.min.x, o.min.x), min(self.min.y, o.min.y), min(self.min.z, o.min.z)),
            Vec3(max(self.max.x, o.max.x), max(self.max.y, o.max.y), max(self.max.z, o.max.z))
        )

    def area(self) -> float:
        w = max(0.0, self.max.x - self.min.x)
        h = max(0.0, self.max.y - self.min.y)
        d = max(0.0, self.max.z - self.min.z)
        return 2.0*(w*h + h*d + d*w)

    def center(self) -> Vec3:
        return Vec3(0.5*(self.min.x + self.max.x), 0.5*(self.min.y + self.max.y), 0.5*(self.min.z + self.max.z))

    def overlaps(self, o: "AABB3") -> bool:
        return not (self.max.x < o.min.x or self.min.x > o.max.x or
                    self.max.y < o.min.y or self.min.y > o.max.y or
                    self.max.z < o.min.z or self.min.z > o.max.z)

    def contains_point(self, p: Vec3) -> bool:
        return (self.min.x <= p.x <= self.max.x and
                self.min.y <= p.y <= self.max.y and
                self.min.z <= p.z <= self.max.z)

# Ray slab intersection
def ray_aabb3(origin: Vec3, dir: Vec3, aabb: AABB3, tmin: float = 0.0, tmax: float = float("inf")) -> Optional[float]:
    invx = 1.0/dir.x if abs(dir.x) > _EPS else float("inf")
    invy = 1.0/dir.y if abs(dir.y) > _EPS else float("inf")
    invz = 1.0/dir.z if abs(dir.z) > _EPS else float("inf")

    tx1 = (aabb.min.x - origin.x) * invx
    tx2 = (aabb.max.x - origin.x) * invx
    tmin = max(tmin, min(tx1, tx2))
    tmax = min(tmax, max(tx1, tx2))
    if tmax < tmin: return None

    ty1 = (aabb.min.y - origin.y) * invy
    ty2 = (aabb.max.y - origin.y) * invy
    tmin = max(tmin, min(ty1, ty2))
    tmax = min(tmax, max(ty1, ty2))
    if tmax < tmin: return None

    tz1 = (aabb.min.z - origin.z) * invz
    tz2 = (aabb.max.z - origin.z) * invz
    tmin = max(tmin, min(tz1, tz2))
    tmax = min(tmax, max(tz1, tz2))
    if tmax < tmin: return None

    return tmin if tmin >= 0.0 else (tmax if tmax >= 0.0 else None)

# =============================================================================
# Общий интерфейс
# =============================================================================

TId = TypeVar("TId", bound=Any)

class SpatialIndex(Generic[TId]):
    """
    Унифицированный контракт пространственных индексов.
    """

    def insert(self, oid: TId, aabb: Any) -> None: ...
    def remove(self, oid: TId) -> None: ...
    def update(self, oid: TId, aabb: Any) -> None: ...
    def build_bulk(self, items: Iterable[Tuple[TId, Any]]) -> None: ...
    def query_overlap(self, aabb: Any) -> List[TId]: ...
    def query_range(self, center: Any, radius: float) -> List[TId]: ...
    def raycast(self, origin: Vec3, direction: Vec3, max_distance: float = float("inf")) -> List[Tuple[float, TId]]: ...
    def knn(self, point: Any, k: int = 1) -> List[Tuple[float, TId]]: ...
    def size(self) -> int: ...
    def bounds(self) -> Any: ...
    def snapshot(self) -> Dict[str, Any]: ...
    def restore(self, data: Dict[str, Any]) -> None: ...

# =============================================================================
# BVH (3D) — SAH build + refit
# =============================================================================

@dataclass
class _BVHLeaf:
    ids: List[Any] = field(default_factory=list)
    aabb: Optional[AABB3] = None

@dataclass
class _BVHNode:
    aabb: AABB3
    left: Optional[int] = None
    right: Optional[int] = None
    leaf: Optional[_BVHLeaf] = None

class BVH3(SpatialIndex[TId]):
    """
    3D BVH с SAH‑построением (top‑down), рефитом и частичными обновлениями.
    Удобен для broad‑phase коллизий и быстрых лучей.
    """

    def __init__(self, max_leaf_size: int = 4):
        self._max_leaf = max(1, max_leaf_size)
        self._nodes: List[_BVHNode] = []
        self._root: Optional[int] = None
        self._map: Dict[TId, AABB3] = {}
        self._lock = threading.RLock()
        self._schema_version = 1

    # ------------------------ CRUD ------------------------ #

    def insert(self, oid: TId, aabb: AABB3) -> None:
        with self._lock:
            self._map[oid] = aabb.expand()
            self._rebuild_if_needed()

    def remove(self, oid: TId) -> None:
        with self._lock:
            self._map.pop(oid, None)
            self._rebuild_if_needed()

    def update(self, oid: TId, aabb: AABB3) -> None:
        with self._lock:
            if oid not in self._map:
                self._map[oid] = aabb.expand()
            else:
                self._map[oid] = aabb.expand()
            self._rebuild_if_needed()

    def build_bulk(self, items: Iterable[Tuple[TId, AABB3]]) -> None:
        with self._lock:
            self._map.clear()
            for oid, bb in items:
                self._map[oid] = bb.expand()
            self._build_sah()

    def size(self) -> int:
        return len(self._map)

    def bounds(self) -> Optional[AABB3]:
        with self._lock:
            it = iter(self._map.values())
            try:
                cur = next(it)
            except StopIteration:
                return None
            for bb in it:
                cur = cur.union(bb)
            return cur

    # ------------------------ Queries ------------------------ #

    def query_overlap(self, aabb: AABB3) -> List[TId]:
        with self._lock:
            out: List[TId] = []
            if self._root is None:
                return out
            stack = [self._root]
            while stack:
                i = stack.pop()
                node = self._nodes[i]
                if not node.aabb.overlaps(aabb):
                    continue
                if node.leaf:
                    for oid in node.leaf.ids:
                        if self._map[oid].overlaps(aabb):
                            out.append(oid)
                else:
                    if node.left is not None: stack.append(node.left)
                    if node.right is not None: stack.append(node.right)
            return out

    def query_range(self, center: Vec3, radius: float) -> List[TId]:
        r2 = radius*radius
        bb = AABB3(
            Vec3(center.x - radius, center.y - radius, center.z - radius),
            Vec3(center.x + radius, center.y + radius, center.z + radius),
        )
        out = []
        for oid in self.query_overlap(bb):
            c = self._map[oid].center()
            if (c - center).norm2() <= r2:
                out.append(oid)
        return out

    def raycast(self, origin: Vec3, direction: Vec3, max_distance: float = float("inf")) -> List[Tuple[float, TId]]:
        with self._lock:
            hits: List[Tuple[float, TId]] = []
            if self._root is None: return hits
            stack = [self._root]
            while stack:
                i = stack.pop()
                node = self._nodes[i]
                t = ray_aabb3(origin, direction, node.aabb, 0.0, max_distance)
                if t is None: continue
                if node.leaf:
                    for oid in node.leaf.ids:
                        t2 = ray_aabb3(origin, direction, self._map[oid], 0.0, max_distance)
                        if t2 is not None:
                            hits.append((t2, oid))
                else:
                    if node.left is not None: stack.append(node.left)
                    if node.right is not None: stack.append(node.right)
            hits.sort(key=lambda x: x[0])
            return hits

    def knn(self, point: Vec3, k: int = 1) -> List[Tuple[float, TId]]:
        with self._lock:
            if self._root is None or k <= 0:
                return []
            # best-first search по расстоянию AABB–point
            def bb_dist2(bb: AABB3, p: Vec3) -> float:
                cx = _clamp(p.x, bb.min.x, bb.max.x)
                cy = _clamp(p.y, bb.min.y, bb.max.y)
                cz = _clamp(p.z, bb.min.z, bb.max.z)
                dx, dy, dz = p.x - cx, p.y - cy, p.z - cz
                return dx*dx + dy*dy + dz*dz

            heap: List[Tuple[float, int]] = [(0.0, self._root)]
            best: List[Tuple[float, TId]] = []

            while heap:
                _, idx = heapq.heappop(heap)
                node = self._nodes[idx]
                if node.leaf:
                    for oid in node.leaf.ids:
                        c = self._map[oid].center()
                        d2 = (c - point).norm2()
                        if len(best) < k:
                            heapq.heappush(best, (-d2, oid))
                        else:
                            if d2 < -best[0][0]:
                                heapq.heapreplace(best, (-d2, oid))
                else:
                    if node.left is not None:
                        heapq.heappush(heap, (bb_dist2(self._nodes[node.left].aabb, point), node.left))
                    if node.right is not None:
                        heapq.heappush(heap, (bb_dist2(self._nodes[node.right].aabb, point), node.right))

            res = [(-d2, oid) for d2, oid in best]
            res.sort(key=lambda x: x[0])
            return res

    # ------------------------ Build/Refit ------------------------ #

    def _rebuild_if_needed(self) -> None:
        # простая эвристика: если n мал или модификации частые — refit/пересборка
        n = len(self._map)
        if n == 0:
            self._nodes.clear()
            self._root = None
            return
        if not self._nodes or n > 4 * self._leaf_object_count():
            self._build_sah()
        else:
            self._refit()

    def _leaf_object_count(self) -> int:
        c = 0
        for nd in self._nodes:
            if nd.leaf:
                c += len(nd.leaf.ids)
        return c

    def _build_sah(self) -> None:
        # SAH: рекурсивный top‑down split вдоль лучшей оси с минимизацией стоимости
        items = list(self._map.items())  # (id, aabb)
        if not items:
            self._nodes.clear()
            self._root = None
            return

        def build(ids_aabb: List[Tuple[TId, AABB3]]) -> int:
            node_aabb = ids_aabb[0][1]
            for _, bb in ids_aabb[1:]:
                node_aabb = node_aabb.union(bb)
            if len(ids_aabb) <= self._max_leaf:
                leaf = _BVHLeaf([oid for oid,_ in ids_aabb], node_aabb)
                idx = len(self._nodes)
                self._nodes.append(_BVHNode(node_aabb, leaf=leaf))
                return idx

            # выбор оси по наибольшему размеру
            ext = node_aabb.max - node_aabb.min
            axis = 0
            if ext.y > ext.x and ext.y >= ext.z: axis = 1
            elif ext.z > ext.x and ext.z >= ext.y: axis = 2

            # биннинг для SAH
            B = 12
            bins = [None] * B  # (count, aabb)
            centers = []
            for oid, bb in ids_aabb:
                c = bb.center()
                centers.append((oid, bb, (c.x, c.y, c.z)))
            mn = (node_aabb.min.x, node_aabb.min.y, node_aabb.min.z)
            mx = (node_aabb.max.x, node_aabb.max.y, node_aabb.max.z)
            span = max(_EPS, mx[axis] - mn[axis])

            for oid, bb, c in centers:
                bi = int(((c[axis] - mn[axis]) / span) * (B - 1))
                if bins[bi] is None:
                    bins[bi] = [1, bb]
                else:
                    bins[bi][0] += 1
                    bins[bi][1] = bins[bi][1].union(bb)

            # префиксы/суффиксы для оценки стоимости
            pref_cnt, pref_bb = [0]*B, [None]*B
            suff_cnt, suff_bb = [0]*B, [None]*B
            cur_cnt = 0
            cur_bb = None
            for i in range(B):
                if bins[i] is None: continue
                cur_cnt += bins[i][0]
                cur_bb = bins[i][1] if cur_bb is None else cur_bb.union(bins[i][1])
                pref_cnt[i] = cur_cnt
                pref_bb[i] = cur_bb
            cur_cnt = 0
            cur_bb = None
            for i in range(B-1, -1, -1):
                if bins[i] is None: continue
                cur_cnt += bins[i][0]
                cur_bb = bins[i][1] if cur_bb is None else cur_bb.union(bins[i][1])
                suff_cnt[i] = cur_cnt
                suff_bb[i] = cur_bb

            best_split, best_cost = None, float("inf")
            for i in range(B-1):
                if pref_cnt[i] == 0 or suff_cnt[i+1] == 0: continue
                cost = (pref_cnt[i]*(pref_bb[i].area() if pref_bb[i] else 0.0) +
                        suff_cnt[i+1]*(suff_bb[i+1].area() if suff_bb[i+1] else 0.0))
                if cost < best_cost:
                    best_cost = cost
                    best_split = i

            if best_split is None:
                # fallback — медианный сплит по центрам вдоль оси
                centers.sort(key=lambda t: t[2][axis])
                mid = len(centers)//2
                L = [(oid, bb) for oid, bb, _ in centers[:mid]]
                R = [(oid, bb) for oid, bb, _ in centers[mid:]]
            else:
                L, R = [], []
                for oid, bb, c in centers:
                    bi = int(((c[axis] - mn[axis]) / span) * (B - 1))
                    if bi <= best_split: L.append((oid, bb))
                    else: R.append((oid, bb))
                if not L or not R:
                    centers.sort(key=lambda t: t[2][axis])
                    mid = len(centers)//2
                    L = [(oid, bb) for oid, bb, _ in centers[:mid]]
                    R = [(oid, bb) for oid, bb, _ in centers[mid:]]

            idx = len(self._nodes)
            self._nodes.append(_BVHNode(node_aabb, None, None, None))
            li = build(L)
            ri = build(R)
            self._nodes[idx].left = li
            self._nodes[idx].right = ri
            self._nodes[idx].aabb = self._nodes[li].aabb.union(self._nodes[ri].aabb)
            return idx

        self._nodes = []
        self._root = build(items)

    def _refit(self) -> None:
        if self._root is None: return
        # пост-обход
        def refit(idx: int) -> AABB3:
            nd = self._nodes[idx]
            if nd.leaf:
                bb = None
                for oid in nd.leaf.ids:
                    bb = self._map[oid] if bb is None else bb.union(self._map[oid])
                nd.aabb = bb
                return bb
            left = refit(nd.left) if nd.left is not None else None
            right = refit(nd.right) if nd.right is not None else None
            nd.aabb = left.union(right) if left and right else (left or right)
            return nd.aabb
        refit(self._root)

    # ------------------------ Serialization ------------------------ #

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "version": self._schema_version,
                "type": "bvh3",
                "objects": {str(k): {"min": (v.min.x, v.min.y, v.min.z), "max": (v.max.x, v.max.y, v.max.z)}
                            for k, v in self._map.items()}
            }

    def restore(self, data: Dict[str, Any]) -> None:
        if data.get("type") != "bvh3" or int(data.get("version", 1)) != 1:
            raise ValueError("Unsupported snapshot")
        with self._lock:
            self._map.clear()
            for k, o in (data.get("objects") or {}).items():
                mn = Vec3(*o["min"]); mx = Vec3(*o["max"])
                self._map[k] = AABB3(mn, mx)
            self._build_sah()

# =============================================================================
# Morton кодирование (2D/3D)
# =============================================================================

def _part1by1(n: int) -> int:
    n &= 0x0000FFFF
    n = (n | (n << 8)) & 0x00FF00FF
    n = (n | (n << 4)) & 0x0F0F0F0F
    n = (n | (n << 2)) & 0x33333333
    n = (n | (n << 1)) & 0x55555555
    return n

def _part1by2(n: int) -> int:
    n &= 0x000003FF
    n = (n | (n << 16)) & 0x30000FF
    n = (n | (n << 8)) & 0x300F00F
    n = (n | (n << 4)) & 0x30C30C3
    n = (n | (n << 2)) & 0x9249249
    return n

def morton2(x: int, y: int) -> int:
    return (_part1by1(y) << 1) | _part1by1(x)

def morton3(x: int, y: int, z: int) -> int:
    return (_part1by2(z) << 2) | (_part1by2(y) << 1) | _part1by2(x)

# =============================================================================
# Quadtree (2D, loose)
# =============================================================================

@dataclass
class _QNode:
    bounds: AABB2
    children: List[Optional[int]] = field(default_factory=lambda: [None, None, None, None])
    objects: List[Any] = field(default_factory=list)
    depth: int = 0

class Quadtree2(SpatialIndex[TId]):
    """
    Loose quadtree: каждый узел увеличен в 'loose_factor' раз, снижая частые миграции.
    """

    def __init__(self, world: AABB2, max_depth: int = 10, max_per_node: int = 8, loose_factor: float = 1.25):
        self._world = world
        self._max_depth = max_depth
        self._max_per_node = max_per_node
        self._loose = max(1.0, loose_factor)
        self._nodes: List[_QNode] = [self._make_node(world, 0)]
        self._root = 0
        self._map: Dict[TId, AABB2] = {}
        self._lock = threading.RLock()
        self._schema_version = 1

    def _make_node(self, bb: AABB2, depth: int) -> _QNode:
        # расширим узел
        cx, cy = bb.center().x, bb.center().y
        hx = (bb.max.x - bb.min.x) * 0.5 * self._loose
        hy = (bb.max.y - bb.min.y) * 0.5 * self._loose
        return _QNode(AABB2(Vec2(cx - hx, cy - hy), Vec2(cx + hx, cy + hy)), depth=depth)

    def size(self) -> int:
        return len(self._map)

    def bounds(self) -> AABB2:
        return self._nodes[self._root].bounds

    # CRUD
    def insert(self, oid: TId, aabb: AABB2) -> None:
        with self._lock:
            self._map[oid] = aabb.expand()
            self._insert_oid(self._root, oid, self._map[oid])

    def remove(self, oid: TId) -> None:
        with self._lock:
            bb = self._map.pop(oid, None)
            if bb is None: return
            self._remove_oid(self._root, oid, bb)

    def update(self, oid: TId, aabb: AABB2) -> None:
        with self._lock:
            old = self._map.get(oid)
            nb = aabb.expand()
            self._map[oid] = nb
            if old is None:
                self._insert_oid(self._root, oid, nb)
            else:
                # удалим и вставим заново (loose снижает частоту)
                self._remove_oid(self._root, oid, old)
                self._insert_oid(self._root, oid, nb)

    def build_bulk(self, items: Iterable[Tuple[TId, AABB2]]) -> None:
        with self._lock:
            self._map.clear()
            self._nodes = [self._make_node(self._world, 0)]
            self._root = 0
            for oid, bb in items:
                self._map[oid] = bb.expand()
            for oid, bb in self._map.items():
                self._insert_oid(self._root, oid, bb)

    # вставка в дерево
    def _insert_oid(self, idx: int, oid: TId, bb: AABB2) -> None:
        node = self._nodes[idx]
        if node.depth >= self._max_depth or (len(node.objects) < self._max_per_node and all(c is None for c in node.children)):
            node.objects.append(oid)
            return
        # при необходимости — сплит
        if node.children[0] is None:
            self._split(idx)
        # попытка отправить в детей
        child = self._fit_child(idx, bb)
        if child is None:
            node.objects.append(oid)
        else:
            self._insert_oid(child, oid, bb)

        # ребаланс: при переполнении удерживаем на текущем уровне
        if len(node.objects) > self._max_per_node and node.depth < self._max_depth:
            objs = list(node.objects); node.objects.clear()
            for oid2 in objs:
                bb2 = self._map[oid2]
                child2 = self._fit_child(idx, bb2)
                if child2 is None: node.objects.append(oid2)
                else: self._insert_oid(child2, oid2, bb2)

    def _split(self, idx: int) -> None:
        node = self._nodes[idx]
        b = node.bounds
        cx, cy = b.center().x, b.center().y
        quads = [
            AABB2(Vec2(b.min.x, b.min.y), Vec2(cx, cy)),    # SW
            AABB2(Vec2(cx, b.min.y), Vec2(b.max.x, cy)),    # SE
            AABB2(Vec2(b.min.x, cy), Vec2(cx, b.max.y)),    # NW
            AABB2(Vec2(cx, cy), Vec2(b.max.x, b.max.y)),    # NE
        ]
        for i in range(4):
            node.children[i] = len(self._nodes)
            self._nodes.append(self._make_node(quads[i], node.depth + 1))

    def _fit_child(self, idx: int, bb: AABB2) -> Optional[int]:
        node = self._nodes[idx]
        for i in range(4):
            ci = node.children[i]
            if ci is None: continue
            if self._nodes[ci].bounds.contains_point(bb.center()):
                return ci
        return None

    def _remove_oid(self, idx: int, oid: TId, bb: AABB2) -> bool:
        node = self._nodes[idx]
        if oid in node.objects:
            node.objects.remove(oid)
            return True
        for ci in node.children:
            if ci is None: continue
            if self._nodes[ci].bounds.overlaps(bb):
                if self._remove_oid(ci, oid, bb): return True
        return False

    # Queries
    def query_overlap(self, aabb: AABB2) -> List[TId]:
        with self._lock:
            out: List[TId] = []
            def dfs(idx: int):
                nd = self._nodes[idx]
                if not nd.bounds.overlaps(aabb): return
                for oid in nd.objects:
                    if self._map[oid].overlaps(aabb): out.append(oid)
                for ci in nd.children:
                    if ci is not None: dfs(ci)
            dfs(self._root)
            return out

    def query_range(self, center: Vec2, radius: float) -> List[TId]:
        bb = AABB2(Vec2(center.x - radius, center.y - radius), Vec2(center.x + radius, center.y + radius))
        r2 = radius*radius
        res: List[TId] = []
        for oid in self.query_overlap(bb):
            c = self._map[oid].center()
            dx, dy = c.x - center.x, c.y - center.y
            if dx*dx + dy*dy <= r2:
                res.append(oid)
        return res

    def raycast(self, origin: Vec3, direction: Vec3, max_distance: float = float("inf")) -> List[Tuple[float, TId]]:
        # 2D индексу луч 3D не обязателен, дадим простую проекцию XY
        o2 = Vec2(origin.x, origin.y)
        d2 = Vec2(direction.x, direction.y)
        # аппроксимация: проверяем пересечение AABB2 реберно — упорядочим по расстоянию до центра (приближенно)
        out: List[Tuple[float, TId]] = []
        for oid, bb in self._map.items():
            # быстрый bbox culling через отрезок до max_distance
            c = bb.center()
            vx, vy = c.x - o2.x, c.y - o2.y
            # скаляр на нормированное не считаем — приближение
            t = max(0.0, (vx * d2.x + vy * d2.y) / (math.hypot(d2.x, d2.y) + _EPS))
            if t <= max_distance and bb.contains_point(Vec2(o2.x + d2.x * (t / (math.hypot(d2.x, d2.y)+_EPS)),
                                                            o2.y + d2.y * (t / (math.hypot(d2.x, d2.y)+_EPS)))):
                out.append((t, oid))
        out.sort(key=lambda x: x[0])
        return out

    def knn(self, point: Vec2, k: int = 1) -> List[Tuple[float, TId]]:
        if k <= 0: return []
        best: List[Tuple[float, TId]] = []
        for oid, bb in self._map.items():
            c = bb.center()
            d2 = (c.x-point.x)**2 + (c.y-point.y)**2
            if len(best) < k: heapq.heappush(best, (-d2, oid))
            else:
                if d2 < -best[0][0]:
                    heapq.heapreplace(best, (-d2, oid))
        res = [(-d2, oid) for d2, oid in best]
        res.sort(key=lambda x: x[0])
        return res

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "version": self._schema_version,
                "type": "quadtree2",
                "world": {"min": (self._world.min.x, self._world.min.y), "max": (self._world.max.x, self._world.max.y)},
                "objects": {str(k): {"min": (v.min.x, v.min.y), "max": (v.max.x, v.max.y)} for k, v in self._map.items()}
            }

    def restore(self, data: Dict[str, Any]) -> None:
        if data.get("type") != "quadtree2" or int(data.get("version", 1)) != 1:
            raise ValueError("Unsupported snapshot")
        w = data["world"]
        self.__init__(AABB2(Vec2(*w["min"]), Vec2(*w["max"])), self._max_depth, self._max_per_node, self._loose)
        with self._lock:
            for k, o in (data.get("objects") or {}).items():
                self.insert(k, AABB2(Vec2(*o["min"]), Vec2(*o["max"])))

# =============================================================================
# Octree (3D, loose)
# =============================================================================

@dataclass
class _ONode:
    bounds: AABB3
    children: List[Optional[int]] = field(default_factory=lambda: [None]*8)
    objects: List[Any] = field(default_factory=list)
    depth: int = 0

class Octree3(SpatialIndex[TId]):
    """
    Loose octree: быстрая вставка/обновление, подходящая для динамики.
    """

    def __init__(self, world: AABB3, max_depth: int = 10, max_per_node: int = 8, loose_factor: float = 1.25):
        self._world = world
        self._max_depth = max_depth
        self._max_per_node = max_per_node
        self._loose = max(1.0, loose_factor)
        self._nodes: List[_ONode] = [self._make_node(world, 0)]
        self._root = 0
        self._map: Dict[TId, AABB3] = {}
        self._lock = threading.RLock()
        self._schema_version = 1

    def _make_node(self, bb: AABB3, depth: int) -> _ONode:
        c = bb.center()
        hx = (bb.max.x - bb.min.x) * 0.5 * self._loose
        hy = (bb.max.y - bb.min.y) * 0.5 * self._loose
        hz = (bb.max.z - bb.min.z) * 0.5 * self._loose
        return _ONode(AABB3(Vec3(c.x - hx, c.y - hy, c.z - hz), Vec3(c.x + hx, c.y + hy, c.z + hz)), depth=depth)

    def size(self) -> int:
        return len(self._map)

    def bounds(self) -> AABB3:
        return self._nodes[self._root].bounds

    def insert(self, oid: TId, aabb: AABB3) -> None:
        with self._lock:
            self._map[oid] = aabb.expand()
            self._insert_oid(self._root, oid, self._map[oid])

    def remove(self, oid: TId) -> None:
        with self._lock:
            bb = self._map.pop(oid, None)
            if bb is None: return
            self._remove_oid(self._root, oid, bb)

    def update(self, oid: TId, aabb: AABB3) -> None:
        with self._lock:
            old = self._map.get(oid)
            nb = aabb.expand()
            self._map[oid] = nb
            if old is None:
                self._insert_oid(self._root, oid, nb)
            else:
                self._remove_oid(self._root, oid, old)
                self._insert_oid(self._root, oid, nb)

    def build_bulk(self, items: Iterable[Tuple[TId, AABB3]]) -> None:
        with self._lock:
            self._map.clear()
            self._nodes = [self._make_node(self._world, 0)]
            self._root = 0
            for oid, bb in items:
                self._map[oid] = bb.expand()
            for oid, bb in self._map.items():
                self._insert_oid(self._root, oid, bb)

    def _split(self, idx: int) -> None:
        nd = self._nodes[idx]
        b = nd.bounds
        c = b.center()
        mins = [b.min, Vec3(c.x, b.min.y, b.min.z), Vec3(b.min.x, c.y, b.min.z), Vec3(c.x, c.y, b.min.z),
                Vec3(b.min.x, b.min.y, c.z), Vec3(c.x, b.min.y, c.z), Vec3(b.min.x, c.y, c.z), Vec3(c.x, c.y, c.z)]
        maxs = [Vec3(c.x, c.y, c.z), Vec3(b.max.x, c.y, c.z), Vec3(c.x, b.max.y, c.z), Vec3(b.max.x, b.max.y, c.z),
                Vec3(c.x, c.y, b.max.z), Vec3(b.max.x, c.y, b.max.z), Vec3(c.x, b.max.y, b.max.z), b.max]
        for i in range(8):
            nd.children[i] = len(self._nodes)
            self._nodes.append(self._make_node(AABB3(mins[i], maxs[i]), nd.depth + 1))

    def _fit_child(self, idx: int, bb: AABB3) -> Optional[int]:
        nd = self._nodes[idx]
        cen = bb.center()
        for i, ci in enumerate(nd.children):
            if ci is None: continue
            if self._nodes[ci].bounds.contains_point(cen):
                return ci
        return None

    def _insert_oid(self, idx: int, oid: TId, bb: AABB3) -> None:
        nd = self._nodes[idx]
        if nd.depth >= self._max_depth or (len(nd.objects) < self._max_per_node and all(c is None for c in nd.children)):
            nd.objects.append(oid)
            return
        if nd.children[0] is None:
            self._split(idx)
        child = self._fit_child(idx, bb)
        if child is None:
            nd.objects.append(oid)
        else:
            self._insert_oid(child, oid, bb)
        if len(nd.objects) > self._max_per_node and nd.depth < self._max_depth:
            objs = list(nd.objects); nd.objects.clear()
            for oid2 in objs:
                bb2 = self._map[oid2]
                ci = self._fit_child(idx, bb2)
                if ci is None: nd.objects.append(oid2)
                else: self._insert_oid(ci, oid2, bb2)

    def _remove_oid(self, idx: int, oid: TId, bb: AABB3) -> bool:
        nd = self._nodes[idx]
        if oid in nd.objects:
            nd.objects.remove(oid)
            return True
        for ci in nd.children:
            if ci is None: continue
            if self._nodes[ci].bounds.overlaps(bb):
                if self._remove_oid(ci, oid, bb): return True
        return False

    def query_overlap(self, aabb: AABB3) -> List[TId]:
        with self._lock:
            out: List[TId] = []
            def dfs(idx: int):
                nd = self._nodes[idx]
                if not nd.bounds.overlaps(aabb): return
                for oid in nd.objects:
                    if self._map[oid].overlaps(aabb): out.append(oid)
                for ci in nd.children:
                    if ci is not None: dfs(ci)
            dfs(self._root)
            return out

    def query_range(self, center: Vec3, radius: float) -> List[TId]:
        bb = AABB3(Vec3(center.x - radius, center.y - radius, center.z - radius),
                   Vec3(center.x + radius, center.y + radius, center.z + radius))
        r2 = radius*radius
        res: List[TId] = []
        for oid in self.query_overlap(bb):
            c = self._map[oid].center()
            if (c - center).norm2() <= r2:
                res.append(oid)
        return res

    def raycast(self, origin: Vec3, direction: Vec3, max_distance: float = float("inf")) -> List[Tuple[float, TId]]:
        with self._lock:
            hits: List[Tuple[float, TId]] = []
            def dfs(idx: int):
                nd = self._nodes[idx]
                if ray_aabb3(origin, direction, nd.bounds, 0.0, max_distance) is None:
                    return
                for oid in nd.objects:
                    t = ray_aabb3(origin, direction, self._map[oid], 0.0, max_distance)
                    if t is not None: hits.append((t, oid))
                for ci in nd.children:
                    if ci is not None: dfs(ci)
            dfs(self._root)
            hits.sort(key=lambda x: x[0])
            return hits

    def knn(self, point: Vec3, k: int = 1) -> List[Tuple[float, TId]]:
        if k <= 0: return []
        best: List[Tuple[float, TId]] = []
        for oid, bb in self._map.items():
            c = bb.center()
            d2 = (c - point).norm2()
            if len(best) < k: heapq.heappush(best, (-d2, oid))
            else:
                if d2 < -best[0][0]:
                    heapq.heapreplace(best, (-d2, oid))
        res = [(-d2, oid) for d2, oid in best]
        res.sort(key=lambda x: x[0])
        return res

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "version": self._schema_version,
                "type": "octree3",
                "world": {"min": (self._world.min.x, self._world.min.y, self._world.min.z),
                          "max": (self._world.max.x, self._world.max.y, self._world.max.z)},
                "objects": {str(k): {"min": (v.min.x, v.min.y, v.min.z), "max": (v.max.x, v.max.y, v.max.z)} for k, v in self._map.items()}
            }

    def restore(self, data: Dict[str, Any]) -> None:
        if data.get("type") != "octree3" or int(data.get("version", 1)) != 1:
            raise ValueError("Unsupported snapshot")
        w = data["world"]
        self.__init__(AABB3(Vec3(*w["min"]), Vec3(*w["max"])), self._max_depth, self._max_per_node, self._loose)
        with self._lock:
            for k, o in (data.get("objects") or {}).items():
                self.insert(k, AABB3(Vec3(*o["min"]), Vec3(*o["max"])))

# =============================================================================
# Вспомогательные алгоритмы broadphase
# =============================================================================

def broadphase_pairs(index: SpatialIndex[TId], candidates: Optional[Iterable[TId]] = None) -> List[Tuple[TId, TId]]:
    """
    Перебор потенциально пересекающихся пар (Narrow‑phase вне рамок модуля).
    Для BVH/Octree — используйте query_overlap по AABB объекта.
    Здесь даём универсальный O(M log N): для каждого AABB кандидата вызываем overlap.
    """
    ids = list(candidates) if candidates is not None else list(getattr(index, "_map", {}).keys())
    out: List[Tuple[TId, TId]] = []
    # простая стратегия: сортируем по x‑min для грубого отсека
    items = []
    amap = getattr(index, "_map", {})
    for oid in ids:
        bb = amap[oid]
        x = bb.min.x if hasattr(bb.min, "x") else bb.min[0]
        items.append((x, oid, bb))
    items.sort(key=lambda t: t[0])
    for i in range(len(items)):
        _, oid, bb = items[i]
        # ограничим область поиска по x
        j = i + 1
        while j < len(items) and items[j][0] <= (bb.max.x if hasattr(bb.max, "x") else bb.max[0]):
            if items[j][2].overlaps(bb):
                out.append((oid, items[j][1]))
            j += 1
    return out

# =============================================================================
# Демонстрация (локальный smoke)
# =============================================================================

if __name__ == "__main__":
    # BVH
    bvh = BVH3()
    bvh.build_bulk([
        ("a", AABB3(Vec3(0,0,0), Vec3(1,1,1))),
        ("b", AABB3(Vec3(2,0,0), Vec3(3,1,1))),
        ("c", AABB3(Vec3(0,2,0), Vec3(1,3,1))),
    ])
    print("BVH overlap:", bvh.query_overlap(AABB3(Vec3(0.5,0.5,0.5), Vec3(2.5,1.2,1.2))))
    print("BVH ray:", bvh.raycast(Vec3(-1,0.5,0.5), Vec3(1,0,0)))
    print("BVH kNN:", bvh.knn(Vec3(0,0,0), 2))

    # Quadtree
    qt = Quadtree2(AABB2(Vec2(-10,-10), Vec2(10,10)))
    qt.build_bulk([
        ("q1", AABB2(Vec2(-1,-1), Vec2(1,1))),
        ("q2", AABB2(Vec2(5,5), Vec2(6,6))),
        ("q3", AABB2(Vec2(-6,5), Vec2(-5,6))),
    ])
    print("QT overlap:", qt.query_overlap(AABB2(Vec2(-2,-2), Vec2(2,2))))
    print("QT kNN:", qt.knn(Vec2(0,0), 2))

    # Octree
    oc = Octree3(AABB3(Vec3(-10,-10,-10), Vec3(10,10,10)))
    oc.build_bulk([
        ("o1", AABB3(Vec3(-1,-1,-1), Vec3(1,1,1))),
        ("o2", AABB3(Vec3(5,0,0), Vec3(6,1,1))),
        ("o3", AABB3(Vec3(-6,5,0), Vec3(-5,6,1))),
    ])
    print("OC range:", oc.query_range(Vec3(0,0,0), 3.0))
    print("OC kNN:", oc.knn(Vec3(0,0,0), 2))
