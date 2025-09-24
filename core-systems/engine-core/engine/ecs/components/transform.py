# -*- coding: utf-8 -*-
"""
ECS Transform Component (industrial-grade)
- 3D TRS (translation, rotation, scale)
- Кватернионы, составление/декомпозиция матриц 4x4
- Иерархия (parent/children), локальные и мировые преобразования
- Ленивое кэширование с dirty-флагами
- Потокобезопасность для записи (RLock)
- Опциональное ускорение NumPy (если доступен)
- Сериализация/десериализация с версией схемы

Зависимости: только стандартная библиотека; NumPy опционален.
"""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Tuple

# -----------------------------------------------------------------------------
# Опциональное ускорение NumPy
# -----------------------------------------------------------------------------
try:
    import numpy as _np  # type: ignore
    _HAS_NP = True
except Exception:
    _HAS_NP = False


# -----------------------------------------------------------------------------
# Константы и утилиты
# -----------------------------------------------------------------------------
_EPS = 1e-9
_TWO_PI = math.tau if hasattr(math, "tau") else 2.0 * math.pi

def _clamp(v: float, lo: float, hi: float) -> float:
    return lo if v < lo else hi if v > hi else v

def _is_close(a: float, b: float, eps: float = _EPS) -> bool:
    return abs(a - b) <= eps

def _safe_div(a: float, b: float, default: float = 0.0) -> float:
    return a / b if abs(b) > _EPS else default


# -----------------------------------------------------------------------------
# Вектор/Кватернион/Матрица — лёгкие структуры без внешних зависимостей
# -----------------------------------------------------------------------------
@dataclass(frozen=True)
class Vec3:
    x: float
    y: float
    z: float

    def __add__(self, o: "Vec3") -> "Vec3":
        return Vec3(self.x + o.x, self.y + o.y, self.z + o.z)

    def __sub__(self, o: "Vec3") -> "Vec3":
        return Vec3(self.x - o.x, self.y - o.y, self.z - o.z)

    def __mul__(self, k: float) -> "Vec3":
        return Vec3(self.x * k, self.y * k, self.z * k)

    __rmul__ = __mul__

    def dot(self, o: "Vec3") -> float:
        return self.x * o.x + self.y * o.y + self.z * o.z

    def cross(self, o: "Vec3") -> "Vec3":
        return Vec3(
            self.y * o.z - self.z * o.y,
            self.z * o.x - self.x * o.z,
            self.x * o.y - self.y * o.x,
        )

    def norm(self) -> float:
        return math.sqrt(self.dot(self))

    def normalized(self) -> "Vec3":
        n = self.norm()
        if n <= _EPS:
            return Vec3(0.0, 0.0, 0.0)
        return self * (1.0 / n)

    def to_tuple(self) -> Tuple[float, float, float]:
        return (self.x, self.y, self.z)

    @staticmethod
    def zero() -> "Vec3":
        return Vec3(0.0, 0.0, 0.0)

    @staticmethod
    def one() -> "Vec3":
        return Vec3(1.0, 1.0, 1.0)


@dataclass(frozen=True)
class Quat:
    # Кватернион w + xi + yj + zk
    w: float
    x: float
    y: float
    z: float

    def normalized(self) -> "Quat":
        n = math.sqrt(self.w * self.w + self.x * self.x + self.y * self.y + self.z * self.z)
        if n <= _EPS:
            return Quat.identity()
        return Quat(self.w / n, self.x / n, self.y / n, self.z / n)

    def __mul__(self, o: "Quat") -> "Quat":
        # Композиция вращений
        w1, x1, y1, z1 = self.w, self.x, self.y, self.z
        w2, x2, y2, z2 = o.w, o.x, o.y, o.z
        return Quat(
            w1 * w2 - x1 * x2 - y1 * y2 - z1 * z2,
            w1 * x2 + x1 * w2 + y1 * z2 - z1 * y2,
            w1 * y2 - x1 * z2 + y1 * w2 + z1 * x2,
            w1 * z2 + x1 * y2 - y1 * x2 + z1 * w2,
        )

    def rotate_vec3(self, v: Vec3) -> Vec3:
        # v' = q * (0,v) * q^-1
        q = self
        qv = Quat(0.0, v.x, v.y, v.z)
        qi = q.inverse()
        r = q * qv * qi
        return Vec3(r.x, r.y, r.z)

    def conjugate(self) -> "Quat":
        return Quat(self.w, -self.x, -self.y, -self.z)

    def inverse(self) -> "Quat":
        n2 = self.w * self.w + self.x * self.x + self.y * self.y + self.z * self.z
        if n2 <= _EPS:
            return Quat.identity()
        c = self.conjugate()
        inv = 1.0 / n2
        return Quat(c.w * inv, c.x * inv, c.y * inv, c.z * inv)

    @staticmethod
    def identity() -> "Quat":
        return Quat(1.0, 0.0, 0.0, 0.0)

    @staticmethod
    def from_axis_angle(axis: Vec3, angle_rad: float) -> "Quat":
        a = axis.normalized()
        s = math.sin(angle_rad * 0.5)
        return Quat(math.cos(angle_rad * 0.5), a.x * s, a.y * s, a.z * s).normalized()

    @staticmethod
    def from_euler_xyz(rx: float, ry: float, rz: float) -> "Quat":
        # Порядок вращений X, затем Y, затем Z (правило правой руки)
        cx, sx = math.cos(rx * 0.5), math.sin(rx * 0.5)
        cy, sy = math.cos(ry * 0.5), math.sin(ry * 0.5)
        cz, sz = math.cos(rz * 0.5), math.sin(rz * 0.5)
        # q = qz * qy * qx в терминах композиции для XYZ
        qx = Quat(cx, sx, 0, 0)
        qy = Quat(cy, 0, sy, 0)
        qz = Quat(cz, 0, 0, sz)
        return (qz * qy * qx).normalized()

    def to_matrix(self) -> "Mat4":
        w, x, y, z = self.w, self.x, self.y, self.z
        xx, yy, zz = x * x, y * y, z * z
        xy, xz, yz = x * y, x * z, y * z
        wx, wy, wz = w * x, w * y, w * z
        # Матрица в правой СК
        m = (
            1 - 2 * (yy + zz), 2 * (xy - wz),     2 * (xz + wy),     0.0,
            2 * (xy + wz),     1 - 2 * (xx + zz), 2 * (yz - wx),     0.0,
            2 * (xz - wy),     2 * (yz + wx),     1 - 2 * (xx + yy), 0.0,
            0.0,               0.0,               0.0,               1.0,
        )
        return Mat4(m)

    @staticmethod
    def look_rotation(forward: Vec3, up: Vec3 = Vec3(0, 1, 0)) -> "Quat":
        f = forward.normalized()
        if f.norm() <= _EPS:
            return Quat.identity()
        r = up.cross(f).normalized()
        if r.norm() <= _EPS:
            # up почти параллелен forward — подберем ортогональный
            r = (Vec3(0, 0, 1) if abs(up.y) > 0.9 else Vec3(0, 1, 0)).cross(f).normalized()
        u = f.cross(r)
        # Матрица базиса RUF -> кватернион
        m = (
            r.x, u.x, f.x, 0.0,
            r.y, u.y, f.y, 0.0,
            r.z, u.z, f.z, 0.0,
            0.0, 0.0, 0.0, 1.0,
        )
        return Mat4(m).to_quat().normalized()


@dataclass(frozen=True)
class Mat4:
    # Матрица 4x4 в row-major виде (16 элементов)
    m: Tuple[float, ...]  # длина 16

    def __post_init__(self):
        if len(self.m) != 16:
            raise ValueError("Mat4 requires 16 elements")

    def __mul__(self, o: "Mat4") -> "Mat4":
        a = self.m
        b = o.m
        if _HAS_NP:
            A = _np.frombuffer(_np.array(a, dtype=_np.float64), dtype=_np.float64).reshape((4, 4))
            B = _np.frombuffer(_np.array(b, dtype=_np.float64), dtype=_np.float64).reshape((4, 4))
            C = A @ B
            return Mat4(tuple(float(x) for x in C.reshape(16)))
        # Наивное перемножение 4x4
        r = [0.0] * 16
        for row in range(4):
            for col in range(4):
                r[row * 4 + col] = (
                    a[row * 4 + 0] * b[0 * 4 + col] +
                    a[row * 4 + 1] * b[1 * 4 + col] +
                    a[row * 4 + 2] * b[2 * 4 + col] +
                    a[row * 4 + 3] * b[3 * 4 + col]
                )
        return Mat4(tuple(r))

    @staticmethod
    def identity() -> "Mat4":
        return Mat4((
            1, 0, 0, 0,
            0, 1, 0, 0,
            0, 0, 1, 0,
            0, 0, 0, 1,
        ))

    @staticmethod
    def from_trs(t: Vec3, r: Quat, s: Vec3) -> "Mat4":
        # TRS = T * R * S
        # S
        sm = (
            s.x, 0,   0,   0,
            0,   s.y, 0,   0,
            0,   0,   s.z, 0,
            0,   0,   0,   1,
        )
        # R
        rm = r.to_matrix().m
        # T
        tm = (
            1, 0, 0, 0,
            0, 1, 0, 0,
            0, 0, 1, 0,
            t.x, t.y, t.z, 1,
        )
        return Mat4(tm) * Mat4(rm) * Mat4(sm)

    def to_quat(self) -> Quat:
        # Конвертация вращения из матрицы в кватернион (устойчивый алгоритм)
        m = self.m
        trace = m[0] + m[5] + m[10]
        if trace > 0.0:
            s = math.sqrt(trace + 1.0) * 2.0
            w = 0.25 * s
            x = (m[9] - m[6]) / s
            y = (m[2] - m[8]) / s
            z = (m[4] - m[1]) / s
        elif (m[0] > m[5]) and (m[0] > m[10]):
            s = math.sqrt(1.0 + m[0] - m[5] - m[10]) * 2.0
            w = (m[9] - m[6]) / s
            x = 0.25 * s
            y = (m[1] + m[4]) / s
            z = (m[2] + m[8]) / s
        elif m[5] > m[10]:
            s = math.sqrt(1.0 + m[5] - m[0] - m[10]) * 2.0
            w = (m[2] - m[8]) / s
            x = (m[1] + m[4]) / s
            y = 0.25 * s
            z = (m[6] + m[9]) / s
        else:
            s = math.sqrt(1.0 + m[10] - m[0] - m[5]) * 2.0
            w = (m[4] - m[1]) / s
            x = (m[2] + m[8]) / s
            y = (m[6] + m[9]) / s
            z = 0.25 * s
        return Quat(w, x, y, z).normalized()

    def decompose(self) -> Tuple[Vec3, Quat, Vec3]:
        # Извлечение t, r, s из матрицы TRS (без сдвига перспективы)
        m = self.m
        t = Vec3(m[12], m[13], m[14])
        # scale как длина столбцов 0..2
        sx = math.sqrt(m[0] * m[0] + m[1] * m[1] + m[2] * m[2])
        sy = math.sqrt(m[4] * m[4] + m[5] * m[5] + m[6] * m[6])
        sz = math.sqrt(m[8] * m[8] + m[9] * m[9] + m[10] * m[10])
        if sx <= _EPS or sy <= _EPS or sz <= _EPS:
            s = Vec3(max(sx, _EPS), max(sy, _EPS), max(sz, _EPS))
            r = Quat.identity()
            return t, r, s
        # Нормализуем базис для извлечения кватерниона
        rm = (
            m[0] / sx, m[1] / sx, m[2] / sx, 0.0,
            m[4] / sy, m[5] / sy, m[6] / sy, 0.0,
            m[8] / sz, m[9] / sz, m[10] / sz, 0.0,
            0.0,       0.0,       0.0,       1.0,
        )
        r = Mat4(rm).to_quat().normalized()
        s = Vec3(sx, sy, sz)
        return t, r, s


# -----------------------------------------------------------------------------
# Transform Component
# -----------------------------------------------------------------------------
@dataclass
class Transform:
    # Локальные компоненты
    local_position: Vec3 = field(default_factory=Vec3.zero)
    local_rotation: Quat = field(default_factory=Quat.identity)
    local_scale: Vec3 = field(default_factory=Vec3.one)

    # Иерархия
    parent: Optional["Transform"] = None
    _children: List["Transform"] = field(default_factory=list, init=False, repr=False)

    # Кэш
    _local_matrix: Mat4 = field(default_factory=Mat4.identity, init=False, repr=False)
    _world_matrix: Mat4 = field(default_factory=Mat4.identity, init=False, repr=False)
    _dirty_local: bool = field(default=True, init=False, repr=False)
    _dirty_world: bool = field(default=True, init=False, repr=False)

    # Потокобезопасность и события
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)
    _on_changed: List[Callable[["Transform"], None]] = field(default_factory=list, init=False, repr=False)

    # Версия схемы сериализации
    _schema_version: int = field(default=1, init=False, repr=False)

    # ---------------- Public API: доступ к направлениям ---------------- #
    def forward(self) -> Vec3:
        # В мировой системе координат
        R = self.world_matrix()
        # Третий столбец базиса (ось Z)
        return Vec3(R.m[8], R.m[9], R.m[10]).normalized()

    def right(self) -> Vec3:
        R = self.world_matrix()
        return Vec3(R.m[0], R.m[1], R.m[2]).normalized()

    def up(self) -> Vec3:
        R = self.world_matrix()
        return Vec3(R.m[4], R.m[5], R.m[6]).normalized()

    # ---------------- Изменение локального состояния ------------------- #
    def set_local_position(self, p: Vec3) -> None:
        with self._lock:
            if p == self.local_position:
                return
            self.local_position = p
            self._mark_dirty(local=True)

    def set_local_rotation(self, q: Quat) -> None:
        with self._lock:
            qn = q.normalized()
            self.local_rotation = qn
            self._mark_dirty(local=True)

    def set_local_scale(self, s: Vec3) -> None:
        with self._lock:
            # Защита от нулевого масштаба
            sx = s.x if abs(s.x) > _EPS else _EPS
            sy = s.y if abs(s.y) > _EPS else _EPS
            sz = s.z if abs(s.z) > _EPS else _EPS
            self.local_scale = Vec3(sx, sy, sz)
            self._mark_dirty(local=True)

    def translate_local(self, v: Vec3) -> None:
        with self._lock:
            self.local_position = self.local_position + v
            self._mark_dirty(local=True)

    def rotate_euler_local(self, rx: float, ry: float, rz: float) -> None:
        with self._lock:
            self.local_rotation = (self.local_rotation * Quat.from_euler_xyz(rx, ry, rz)).normalized()
            self._mark_dirty(local=True)

    def rotate_axis_angle_local(self, axis: Vec3, angle_rad: float) -> None:
        with self._lock:
            self.local_rotation = (self.local_rotation * Quat.from_axis_angle(axis, angle_rad)).normalized()
            self._mark_dirty(local=True)

    def look_at(self, target_world: Vec3, up: Vec3 = Vec3(0, 1, 0)) -> None:
        # Устанавливает локальный поворот так, чтобы forward смотрел на target в мировых координатах
        with self._lock:
            pos = self.world_position()
            dirv = (target_world - pos).normalized()
            q_world = Quat.look_rotation(dirv, up)
            # Переводим к локальному относительно родителя
            if self.parent:
                parent_q = self.parent.world_rotation()
                q_local = (parent_q.inverse() * q_world).normalized()
            else:
                q_local = q_world
            self.local_rotation = q_local
            self._mark_dirty(local=True)

    # ---------------- Доступ к локальным/мировым матрицам ---------------- #
    def local_matrix(self) -> Mat4:
        with self._lock:
            if self._dirty_local:
                self._local_matrix = Mat4.from_trs(self.local_position, self.local_rotation, self.local_scale)
                self._dirty_local = False
            return self._local_matrix

    def world_matrix(self) -> Mat4:
        with self._lock:
            if self._dirty_world:
                if self.parent is not None:
                    self._world_matrix = self.parent.world_matrix() * self.local_matrix()
                else:
                    self._world_matrix = self.local_matrix()
                self._dirty_world = False
            return self._world_matrix

    # ---------------- Вычисление мировых TRS ---------------- #
    def world_position(self) -> Vec3:
        m = self.world_matrix().m
        return Vec3(m[12], m[13], m[14])

    def world_rotation(self) -> Quat:
        # Из world_matrix удалим масштаб и извлечем quat
        t, r, s = self.world_matrix().decompose()
        return r

    def world_scale(self) -> Vec3:
        t, r, s = self.world_matrix().decompose()
        return s

    # ---------------- Иерархия ---------------- #
    def add_child(self, child: "Transform", keep_world: bool = True) -> None:
        if child is self:
            raise ValueError("Cannot parent transform to itself")
        with self._lock:
            if child.parent is self:
                return
            # Сохраняем мировое состояние ребенка (опционально)
            child_world = child.world_matrix()
            # Отвязываем от старого родителя
            if child.parent:
                child.parent._remove_child_ref(child)
            # Назначаем нового
            child.parent = self
            self._children.append(child)
            # Пересчет локального состояния исходя из желаемого мирового
            if keep_world:
                inv_parent = self.world_matrix_inv()
                local_mat = inv_parent * child_world
                t, r, s = local_mat.decompose()
                child.local_position = t
                child.local_rotation = r
                child.local_scale = s
            child._mark_dirty(local=True)

    def _remove_child_ref(self, child: "Transform") -> None:
        with self._lock:
            try:
                self._children.remove(child)
            except ValueError:
                pass

    def remove_child(self, child: "Transform", keep_world: bool = True) -> None:
        with self._lock:
            if child not in self._children:
                return
            world = child.world_matrix() if keep_world else None
            self._children.remove(child)
            child.parent = None
            if keep_world and world:
                t, r, s = world.decompose()
                child.local_position, child.local_rotation, child.local_scale = t, r, s
            child._mark_dirty(local=True)

    def set_parent(self, new_parent: Optional["Transform"], keep_world: bool = True) -> None:
        if new_parent is self.parent:
            return
        if new_parent is self:
            raise ValueError("Cannot parent transform to itself")
        if new_parent and self._is_in_subtree(new_parent):
            raise ValueError("Cannot set child as parent (cycle)")
        if self.parent:
            self.parent.remove_child(self, keep_world=keep_world)
        if new_parent:
            new_parent.add_child(self, keep_world=keep_world)

    def children(self) -> Iterable["Transform"]:
        return tuple(self._children)

    def _is_in_subtree(self, node: "Transform") -> bool:
        cur = node
        while cur:
            if cur is self:
                return True
            cur = cur.parent
        return False

    # ---------------- Инверсии/ортонормализация ---------------- #
    def world_matrix_inv(self) -> Mat4:
        # Инверсия аффинной TRS (без перспективы) — аналитически
        t, r, s = self.world_matrix().decompose()
        # inv(TRS) = inv(S) * inv(R) * inv(T)
        inv_s = Vec3(_safe_div(1.0, s.x, 1.0), _safe_div(1.0, s.y, 1.0), _safe_div(1.0, s.z, 1.0))
        inv_r = r.inverse()
        inv_t = Vec3(-t.x, -t.y, -t.z)
        return Mat4.from_trs(Vec3.zero(), inv_r, inv_s) * Mat4.from_trs(inv_t, Quat.identity(), Vec3.one())

    def orthonormalize_local_rotation(self) -> None:
        # Перенормировать кватернион (устранить накопление ошибок)
        with self._lock:
            self.local_rotation = self.local_rotation.normalized()
            self._mark_dirty(local=True)

    # ---------------- Сериализация ---------------- #
    def to_dict(self) -> Dict:
        return {
            "version": self._schema_version,
            "local": {
                "position": self.local_position.to_tuple(),
                "rotation": (self.local_rotation.w, self.local_rotation.x, self.local_rotation.y, self.local_rotation.z),
                "scale": self.local_scale.to_tuple(),
            },
        }

    @staticmethod
    def from_dict(data: Dict) -> "Transform":
        ver = int(data.get("version", 1))
        if ver != 1:
            # Для иного формата могут потребоваться миграции
            raise ValueError(f"Unsupported Transform schema version: {ver}")
        lp = data["local"]["position"]
        lr = data["local"]["rotation"]
        ls = data["local"]["scale"]
        return Transform(
            local_position=Vec3(*lp),
            local_rotation=Quat(*lr).normalized(),
            local_scale=Vec3(*ls),
        )

    # ---------------- Подписчики изменений ---------------- #
    def on_changed(self, cb: Callable[["Transform"], None]) -> None:
        with self._lock:
            self._on_changed.append(cb)

    # ---------------- Внутреннее: dirty‑протокол ---------------- #
    def _mark_dirty(self, *, local: bool = False, world: bool = True) -> None:
        # Помечаем себя и детей; выбрасываем событие
        with self._lock:
            if local:
                self._dirty_local = True
                self._dirty_world = True
            if world:
                self._dirty_world = True
            # Каскад детям
            for ch in self._children:
                ch._mark_dirty(world=True)
            # Коллбеки вне блокировки
        for cb in list(self._on_changed):
            try:
                cb(self)
            except Exception:
                pass


# -----------------------------------------------------------------------------
# Пример использования (локальный smoke)
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    root = Transform()
    a = Transform()
    b = Transform()

    root.add_child(a)
    a.add_child(b)

    a.set_local_position(Vec3(1, 0, 0))
    a.rotate_axis_angle_local(Vec3(0, 1, 0), math.radians(90))
    b.set_local_position(Vec3(0, 0, 2))

    print("A world pos:", a.world_position())
    print("B world pos:", b.world_position())
    print("B forward :", b.forward())
    # Проверка look_at
    b.look_at(Vec3(0, 0, 0))
    print("B rot after look_at (quat):", b.local_rotation)
