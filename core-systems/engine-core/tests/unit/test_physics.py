# engine-core/engine/tests/unit/test_physics.py
# Industrial-grade tests for physics core.
# Requirements:
#   - pytest
#   - hypothesis (property-based)
# Optional:
#   - numpy (faster vector checks; tests gracefully fallback if absent)
#
# Expected SUT API (module: engine.physics):
#   vec3(x, y, z) -> tuple[float, float, float] | numpy array
#   add(a,b) -> vec3
#   sub(a,b) -> vec3
#   mul(a, s: float) -> vec3   (scalar multiply)
#   dot(a,b) -> float
#   length(a) -> float
#   normalize(a) -> vec3
#
#   integrate_euler(p: vec3, v: vec3, a: vec3, dt: float) -> (p2, v2)
#   integrate_rk4(   p: vec3, v: vec3, a: vec3, dt: float) -> (p2, v2)
#
#   gravity(m: float, g: float = 9.80665) -> vec3 (direction along -Y: (0,-m*g,0))
#   drag(v: vec3, rho: float, Cd: float, area: float) -> vec3
#
#   collide_spheres(p1, r1, p2, r2) -> dict(
#       colliding: bool, penetration: float, normal: vec3  # normal from p1 to p2 (unit) if colliding else (0,0,0)
#   )
#   resolve_collision(p1,v1,m1, p2,v2,m2, normal, restitution: float) -> ((p1c,v1c), (p2c,v2c))
#
#   aabb_overlap(a_min, a_max, b_min, b_max) -> bool
#
# If your module exposes equivalent names via a class, provide top-level wrappers or adjust here.

import importlib
import math
import os
from typing import Any, Tuple

import pytest
from hypothesis import given, settings, strategies as st

try:
    import numpy as _np  # Optional accel
except Exception:  # pragma: no cover
    _np = None  # type: ignore


# ---------------------------------------------------------------------------
# SUT import and capability checks
# ---------------------------------------------------------------------------

def _require_module():
    try:
        return importlib.import_module("engine.physics")
    except Exception as e:  # pragma: no cover
        pytest.fail(
            "Не найден модуль 'engine.physics'. "
            "Создайте файл engine/physics.py с API, описанным в шапке теста. "
            f"Оригинальная ошибка импорта: {e}"
        )

physics = _require_module()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def v3(x: float, y: float, z: float):
    """Create a vector in the SUT representation (tuple or numpy)."""
    return physics.vec3(float(x), float(y), float(z))

def to_tuple(v) -> Tuple[float, float, float]:
    if _np is not None and isinstance(v, _np.ndarray):
        return (float(v[0]), float(v[1]), float(v[2]))
    if isinstance(v, (list, tuple)) and len(v) == 3:
        return (float(v[0]), float(v[1]), float(v[2]))
    # best effort for custom types with x,y,z
    return (float(v.x), float(v.y), float(v.z))

def almost_vec(a, b, rel=1e-7, abs_=1e-8, msg=""):
    at = to_tuple(a)
    bt = to_tuple(b)
    for i in range(3):
        assert math.isfinite(at[i]) and math.isfinite(bt[i]), f"NaN/inf компонент {i} {msg}"
        assert math.isclose(at[i], bt[i], rel_tol=rel, abs_tol=abs_), f"vec mismatch[{i}]: {at} vs {bt} {msg}"


# ---------------------------------------------------------------------------
# Unit tests: basic vector ops
# ---------------------------------------------------------------------------

@given(
    st.tuples(st.floats(-1e6, 1e6, allow_nan=False, allow_infinity=False),
              st.floats(-1e6, 1e6, allow_nan=False, allow_infinity=False),
              st.floats(-1e6, 1e6, allow_nan=False, allow_infinity=False)),
    st.floats(-1e6, 1e6, allow_nan=False, allow_infinity=False),
)
@settings(deadline=None, max_examples=200)
def test_vec_ops_properties(p_xyz, scalar):
    ax, ay, az = p_xyz
    a = v3(ax, ay, az)
    zero = v3(0.0, 0.0, 0.0)
    # a + 0 = a
    almost_vec(physics.add(a, zero), a, msg="a+0=a")
    # a - a = 0
    almost_vec(physics.sub(a, a), zero, msg="a-a=0")
    # dot(a, a) = ||a||^2
    la2 = physics.dot(a, a)
    la = physics.length(a)
    assert math.isclose(la2, la * la, rel_tol=1e-9, abs_tol=1e-10)
    # normalize(a) has length 1 (unless zero)
    if physics.length(a) > 0:
        na = physics.normalize(a)
        assert math.isclose(physics.length(na), 1.0, rel_tol=1e-7, abs_tol=1e-8)


# ---------------------------------------------------------------------------
# Forces: gravity and drag
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("m,g", [(1.0, 9.80665), (70.0, 9.81), (0.5, 1.62)])  # Earth, approx, Moon
def test_gravity_vector(m, g):
    F = physics.gravity(m, g)
    almost_vec(F, v3(0, -m * g, 0), abs_=1e-12)

@pytest.mark.parametrize("v,rho,Cd,A", [
    ((10,0,0), 1.225, 1.0, 1.0),
    ((0,20,0), 1.0, 0.47, 0.3),
    ((-5,0,12), 1.225, 1.05, 0.7),
])
def test_drag_direction_and_magnitude(v, rho, Cd, A):
    vvec = v3(*v)
    Fd = physics.drag(vvec, rho, Cd, A)
    # Direction opposite to velocity (or zero if v == 0)
    speed = physics.length(vvec)
    if speed == 0:
        almost_vec(Fd, v3(0,0,0))
        return
    # Fd = -0.5 * rho * Cd * A * |v| * v_hat
    expected = physics.mul(physics.normalize(vvec), -0.5 * rho * Cd * A * speed)
    almost_vec(Fd, expected, rel=1e-7, abs_=1e-9)


# ---------------------------------------------------------------------------
# Integrators: Euler (semi-implicit) and RK4 vs analytic solutions
# ---------------------------------------------------------------------------

def _analytic_free_fall(p0, v0, a, dt):
    # p(t) = p0 + v0*t + 0.5*a*t^2 ; v(t) = v0 + a*t
    px = p0[0] + v0[0]*dt + 0.5*a[0]*dt*dt
    py = p0[1] + v0[1]*dt + 0.5*a[1]*dt*dt
    pz = p0[2] + v0[2]*dt + 0.5*a[2]*dt*dt
    vx = v0[0] + a[0]*dt
    vy = v0[1] + a[1]*dt
    vz = v0[2] + a[2]*dt
    return (px,py,pz), (vx,vy,vz)

@pytest.mark.parametrize("dt", [1e-4, 1e-3, 1e-2, 1e-1])
def test_integrate_against_analytic_uniform_accel(dt):
    p0 = v3(0, 10, 0)
    v0 = v3(3, 0, 0)
    a  = v3(0, -9.80665, 0)
    p_eu, v_eu = physics.integrate_euler(p0, v0, a, dt)
    p_rk, v_rk = physics.integrate_rk4(p0, v0, a, dt)
    p_an, v_an = _analytic_free_fall(to_tuple(p0), to_tuple(v0), to_tuple(a), dt)
    # RK4 должен быть точнее, чем semi-implicit Euler
    err_eu = math.dist(to_tuple(p_eu), p_an) + math.dist(to_tuple(v_eu), v_an)
    err_rk = math.dist(to_tuple(p_rk), p_an) + math.dist(to_tuple(v_rk), v_an)
    assert err_rk <= err_eu + 1e-12
    # Абсолютная ошибка в разумных пределах
    assert err_eu < 1e-2 if dt <= 1e-2 else err_eu < 5e-1
    assert err_rk < 1e-6 if dt <= 1e-2 else err_rk < 1e-2

def test_energy_monotonicity_with_drag():
    # Демпфированная система должна терять механическую энергию
    m = 2.0
    p = v3(0, 100, 0)
    v = v3(0, 0, 0)
    g = physics.gravity(m, 9.80665)
    rho, Cd, A = 1.225, 1.0, 0.3
    dt = 1/240
    prev_E = float("inf")
    for _ in range(1200):  # 5 секунд
        a = physics.mul(g, 1.0 / m)  # суммарная сила пока g+drag, drag добавим к ускорению ниже
        Fd = physics.drag(v, rho, Cd, A)
        a = physics.add(a, physics.mul(Fd, 1.0/m))
        p, v = physics.integrate_euler(p, v, a, dt)
        # Полная энергия: E = m g h + 0.5 m |v|^2  (ослабляется из‑за drag)
        h = to_tuple(p)[1]
        E = m * 9.80665 * max(h, 0.0) + 0.5 * m * (physics.length(v) ** 2)
        assert E <= prev_E + 1e-6  # монотонно невозрастающая
        prev_E = E


# ---------------------------------------------------------------------------
# Collisions: spheres and AABB
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("p1,r1,p2,r2,expected_pen", [
    ((0,0,0), 1.0, (1.5,0,0), 1.0, 0.5),
    ((0,0,0), 1.0, (3.0,0,0), 1.0, 0.0),
    ((0,0,0), 2.0, (1.0,1.0,0), 1.5, 2.5 - math.sqrt(2)),
])
def test_collide_spheres_penetration(p1,r1,p2,r2,expected_pen):
    res = physics.collide_spheres(v3(*p1), r1, v3(*p2), r2)
    assert isinstance(res, dict) and "colliding" in res and "penetration" in res and "normal" in res
    pen = float(res["penetration"])
    colliding = bool(res["colliding"])
    if expected_pen > 0:
        assert colliding
        assert pen == pytest.approx(expected_pen, rel=1e-7, abs=1e-8)
        n = to_tuple(res["normal"])
        # Нормаль единичной длины и направлена от p1 к p2
        assert math.isclose(math.sqrt(n[0]**2 + n[1]**2 + n[2]**2), 1.0, rel_tol=1e-7, abs_tol=1e-8)
        d = tuple(b - a for a, b in zip(p1, p2))
        dot = n[0]*d[0] + n[1]*d[1] + n[2]*d[2]
        assert dot > 0
    else:
        assert not colliding
        assert pen == 0.0

@pytest.mark.parametrize("a_min,a_max,b_min,b_max,overlap", [
    ((0,0,0),(1,1,1), (0.5,0.5,0.5),(2,2,2), True),
    ((0,0,0),(1,1,1), (1.0,1.0,1.0),(2,2,2), True),  # касание по ребру считается пересечением
    ((0,0,0),(1,1,1), (1.01,1.0,1.0),(2,2,2), False),
])
def test_aabb_overlap(a_min, a_max, b_min, b_max, overlap):
    got = physics.aabb_overlap(v3(*a_min), v3(*a_max), v3(*b_min), v3(*b_max))
    assert bool(got) is overlap


def test_resolve_collision_conservation_1d():
    # Два шара одинаковой массы, упругое центральное столкновение → обмен скоростями
    m1 = m2 = 1.0
    p1, v1 = v3(-1,0,0), v3(1,0,0)
    p2, v2 = v3( 1,0,0), v3(-1,0,0)
    normal = v3(1,0,0)  # от p1 к p2
    ((_, v1c), (_, v2c)) = physics.resolve_collision(p1,v1,m1, p2,v2,m2, normal, restitution=1.0)
    almost_vec(v1c, v2)
    almost_vec(v2c, v1)
    # Импульс и кинетическая энергия сохраняются
    ke_before = 0.5*m1*(physics.length(v1)**2) + 0.5*m2*(physics.length(v2)**2)
    ke_after  = 0.5*m1*(physics.length(v1c)**2) + 0.5*m2*(physics.length(v2c)**2)
    assert ke_after == pytest.approx(ke_before, rel=1e-7, abs=1e-9)

@pytest.mark.parametrize("e", [0.0, 0.25, 0.5, 0.9, 1.0])
def test_resolve_collision_energy_not_increasing(e):
    # При коэффициенте реституции e ∈ [0,1] энергия не должна расти
    m1 = 2.0; m2 = 3.0
    p1, v1 = v3(0,0,0), v3( 3, 0, 0)
    p2, v2 = v3(0,0,0), v3(-1, 0, 0)
    n = v3(1,0,0)
    ((_, v1c), (_, v2c)) = physics.resolve_collision(p1,v1,m1, p2,v2,m2, n, restitution=e)
    ke_before = 0.5*m1*(physics.length(v1)**2) + 0.5*m2*(physics.length(v2)**2)
    ke_after  = 0.5*m1*(physics.length(v1c)**2) + 0.5*m2*(physics.length(v2c)**2)
    assert ke_after <= ke_before + 1e-10


# ---------------------------------------------------------------------------
# Integrator stability on SHO (simple harmonic oscillator)
# x'' + (k/m) x = 0 ; analytic period T = 2π sqrt(m/k)
# ---------------------------------------------------------------------------

def _sho_energy(m, k, x, v):
    # E = 1/2 k x^2 + 1/2 m v^2
    return 0.5*k*(x**2) + 0.5*m*(v**2)

@pytest.mark.parametrize("dt", [1/240, 1/120, 1/60])
def test_sho_energy_stability_rk4(dt):
    m, k = 1.0, 4.0
    x, v = 1.0, 0.0
    p = v3(x, 0, 0)
    vel = v3(v, 0, 0)

    steps = int(3.0 / dt)  # 3s
    E0 = _sho_energy(m, k, x, v)
    for _ in range(steps):
        # acceleration a = -(k/m) x
        a = v3(-(k/m)*to_tuple(p)[0], 0, 0)
        p, vel = physics.integrate_rk4(p, vel, a, dt)
    x_end = to_tuple(p)[0]
    v_end = to_tuple(vel)[0]
    E1 = _sho_energy(m, k, x_end, v_end)
    # RK4 должен сохранять энергию существенно лучше, чем простой Euler
    assert math.isclose(E1, E0, rel_tol=5e-3, abs_tol=5e-4)


# ---------------------------------------------------------------------------
# Determinism & regression
# ---------------------------------------------------------------------------

def test_determinism_fixed_step_sequence():
    p = v3(0, 1, 0)
    v = v3(1, 2, 3)
    a = v3(0, -9.81, 0)
    dt = 1/120
    seq1 = []
    seq2 = []
    p1, v1 = p, v
    for _ in range(100):
        p1, v1 = physics.integrate_euler(p1, v1, a, dt)
        seq1.append((to_tuple(p1), to_tuple(v1)))
    p2, v2 = p, v
    for _ in range(100):
        p2, v2 = physics.integrate_euler(p2, v2, a, dt)
        seq2.append((to_tuple(p2), to_tuple(v2)))
    assert seq1 == seq2


# ---------------------------------------------------------------------------
# Performance hints (not strict): mark.slow if needed
# ---------------------------------------------------------------------------

@pytest.mark.performance
def test_bulk_collisions_scaling(benchmark):
    # Псевдо‑бенчмарк: N попарных проверок пересечения сфер
    import random
    N = 2000
    pts = [(random.uniform(-100,100), random.uniform(-100,100), random.uniform(-100,100)) for _ in range(N)]
    rs  = [random.uniform(0.1, 2.0) for _ in range(N)]
    def _run():
        c = 0
        for i in range(N):
            for j in range(i+1, min(N, i+50)):  # ограничим степень для быстроты
                res = physics.collide_spheres(v3(*pts[i]), rs[i], v3(*pts[j]), rs[j])
                if res["colliding"]:
                    c += 1
        return c
    count = benchmark(_run)
    assert isinstance(count, int)
