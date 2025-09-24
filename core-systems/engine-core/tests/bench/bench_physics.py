# engine-core/engine/tests/bench/bench_physics.py
# Industrial-grade physics microbenchmarks for pytest / pytest-benchmark
#
# SUT expectations (engine.physics):
#   vec3(x,y,z) -> vec3; add/sub/mul/dot/length/normalize
#   integrate_euler(p,v,a,dt) -> (p2,v2)
#   integrate_rk4(p,v,a,dt)    -> (p2,v2)
#   gravity(m,g=9.80665) -> vec3
#   drag(v, rho, Cd, area) -> vec3
#   collide_spheres(p1,r1,p2,r2) -> {colliding:bool, penetration:float, normal:vec3}
#   aabb_overlap(a_min,a_max,b_min,b_max) -> bool
#
# Run:
#   pytest -q engine/tests/bench/bench_physics.py --benchmark-autosave
#   (optional) PYTEST_ADDOPTS="--benchmark-disable" python -m engine.tests.bench.bench_physics
#
# Tuning via env:
#   PHYS_N              total particle count (default 20000)
#   PHYS_STEPS          integration steps per benchmark (default 200)
#   PHYS_COLLISION_N    collision pool size (default 4000)
#   PHYS_SEED           RNG seed (default 1337)
#   PHYS_DT_MIN/MAX     dt range for dt-scaling bench (default 1/240 .. 1/30)
#
from __future__ import annotations

import importlib
import math
import os
import random
import time
from dataclasses import dataclass
from typing import List, Tuple

import pytest

# -----------------------------
# Config knobs (env overrides)
# -----------------------------
N_PARTICLES = int(os.environ.get("PHYS_N", "20000"))
N_STEPS = int(os.environ.get("PHYS_STEPS", "200"))
N_COLLISION = int(os.environ.get("PHYS_COLLISION_N", "4000"))
SEED = int(os.environ.get("PHYS_SEED", "1337"))
DT_MIN = float(os.environ.get("PHYS_DT_MIN", str(1/240)))
DT_MAX = float(os.environ.get("PHYS_DT_MAX", str(1/30)))

# -----------------------------
# Import SUT
# -----------------------------
def _require_module():
    try:
        return importlib.import_module("engine.physics")
    except Exception as e:
        pytest.skip(f"Не найден модуль engine.physics: {e}", allow_module_level=True)

physics = _require_module()

# -----------------------------
# Optional numpy accel
# -----------------------------
try:
    import numpy as np  # type: ignore
except Exception:  # pragma: no cover
    np = None  # type: ignore

# -----------------------------
# Helpers / data generation
# -----------------------------
@dataclass
class Particle:
    p: object
    v: object
    m: float
    A: float  # area for drag

def v3(x: float, y: float, z: float):
    return physics.vec3(float(x), float(y), float(z))

def _rng():
    rnd = random.Random(SEED)
    return rnd

def gen_particles(n: int) -> List[Particle]:
    rnd = _rng()
    out: List[Particle] = []
    for _ in range(n):
        p = v3(rnd.uniform(-100, 100), rnd.uniform(0, 200), rnd.uniform(-100, 100))
        v = v3(rnd.uniform(-5, 5), rnd.uniform(-5, 5), rnd.uniform(-5, 5))
        m = rnd.uniform(0.2, 5.0)
        A = rnd.uniform(0.05, 0.9)
        out.append(Particle(p, v, m, A))
    return out

def gen_spheres(n: int) -> List[Tuple[object, float]]:
    rnd = _rng()
    spheres: List[Tuple[object, float]] = []
    for _ in range(n):
        p = v3(rnd.uniform(-50, 50), rnd.uniform(-50, 50), rnd.uniform(-50, 50))
        r = rnd.uniform(0.1, 2.5)
        spheres.append((p, r))
    return spheres

def gen_aabbs(n: int) -> List[Tuple[object, object]]:
    rnd = _rng()
    boxes = []
    for _ in range(n):
        x, y, z = rnd.uniform(-50, 50), rnd.uniform(-50, 50), rnd.uniform(-50, 50)
        sx, sy, sz = rnd.uniform(0.1, 5.0), rnd.uniform(0.1, 5.0), rnd.uniform(0.1, 5.0)
        a_min = v3(x, y, z)
        a_max = v3(x + sx, y + sy, z + sz)
        boxes.append((a_min, a_max))
    return boxes

def warmup(func, *args, rounds: int = 3, **kwargs):
    for _ in range(rounds):
        func(*args, **kwargs)

# -----------------------------
# Local timer fallback
# -----------------------------
def _manual_bench(fn, iters: int = 1) -> float:
    t0 = time.perf_counter()
    for _ in range(iters):
        fn()
    return (time.perf_counter() - t0) / max(1, iters)

# -----------------------------
# Fixtures
# -----------------------------
@pytest.fixture(scope="session")
def particles() -> List[Particle]:
    return gen_particles(N_PARTICLES)

@pytest.fixture(scope="session")
def spheres_pool() -> List[Tuple[object, float]]:
    return gen_spheres(N_COLLISION)

@pytest.fixture(scope="session")
def aabbs_pool() -> List[Tuple[object, object]]:
    return gen_aabbs(N_COLLISION)

# -----------------------------
# Benchmarks: Vector math
# -----------------------------
@pytest.mark.benchmark(group="vec")
def test_vec_math_dot_length_normalize(benchmark):
    rnd = _rng()
    vecs = [v3(rnd.uniform(-1,1), rnd.uniform(-1,1), rnd.uniform(-1,1)) for _ in range(100000)]

    def work():
        acc = 0.0
        for i in range(0, len(vecs), 2):
            a = vecs[i]
            b = vecs[i+1] if i+1 < len(vecs) else vecs[0]
            acc += physics.dot(a, b)
            acc += physics.length(a)
            _ = physics.normalize(b)
        return acc

    warmup(work)
    res = benchmark(work)
    assert res is not None  # ensures function executed

# -----------------------------
# Benchmarks: Integrators
# -----------------------------
@pytest.mark.benchmark(group="integrate")
@pytest.mark.parametrize("integrator", ["euler", "rk4"])
def test_integrate_particles_with_drag_and_gravity(benchmark, particles, integrator):
    rho, Cd = 1.225, 1.0
    dt = 1/120

    def step_once():
        for i in range(len(particles)):
            pi = particles[i]
            g = physics.gravity(pi.m, 9.80665)
            Fd = physics.drag(pi.v, rho, Cd, pi.A)  # depends on v
            a = physics.mul(g, 1.0/pi.m)
            a = physics.add(a, physics.mul(Fd, 1.0/pi.m))
            if integrator == "euler":
                p2, v2 = physics.integrate_euler(pi.p, pi.v, a, dt)
            else:
                p2, v2 = physics.integrate_rk4(pi.p, pi.v, a, dt)
            pi.p, pi.v = p2, v2

    # do N_STEPS steps per run
    def work():
        for _ in range(N_STEPS):
            step_once()

    warmup(work, rounds=1)
    benchmark(work)

# -----------------------------
# Benchmarks: Collisions (spheres)
# -----------------------------
@pytest.mark.benchmark(group="collision_spheres")
def test_broadphase_spheres_pair_checks(benchmark, spheres_pool):
    # Limit degree to simulate grid bucket adjacency (not full N^2).
    window = 32
    idx = list(range(len(spheres_pool)))

    def work():
        hit = 0
        for i in range(len(idx)):
            p1, r1 = spheres_pool[i]
            for j in range(i+1, min(len(idx), i+1+window)):
                p2, r2 = spheres_pool[j]
                res = physics.collide_spheres(p1, r1, p2, r2)
                hit += 1 if res["colliding"] else 0
        return hit

    warmup(work)
    res = benchmark(work)
    assert isinstance(res, int)

# -----------------------------
# Benchmarks: AABB overlap
# -----------------------------
@pytest.mark.benchmark(group="collision_aabb")
def test_broadphase_aabb_overlap(benchmark, aabbs_pool):
    window = 48

    def work():
        cnt = 0
        for i in range(len(aabbs_pool)):
            a_min, a_max = aabbs_pool[i]
            for j in range(i+1, min(len(aabbs_pool), i+1+window)):
                b_min, b_max = aabbs_pool[j]
                if physics.aabb_overlap(a_min, a_max, b_min, b_max):
                    cnt += 1
        return cnt

    warmup(work)
    res = benchmark(work)
    assert isinstance(res, int)

# -----------------------------
# Benchmarks: dt scaling
# -----------------------------
@pytest.mark.benchmark(group="dt_scale")
@pytest.mark.parametrize("dt", [DT_MIN, (DT_MIN+DT_MAX)/2.0, DT_MAX])
def test_integrator_dt_scaling(benchmark, dt):
    # One particle, many steps — highlight arithmetic intensity vs control overhead
    p = v3(0, 100, 0)
    v = v3(5, 0, 0)
    a_const = v3(0, -9.80665, 0)
    steps = max(1000, int(3.0 / dt))

    def work_euler():
        nonlocal p, v
        pp, vv = p, v
        for _ in range(steps):
            pp, vv = physics.integrate_euler(pp, vv, a_const, dt)
        return pp, vv

    def work_rk4():
        nonlocal p, v
        pp, vv = p, v
        for _ in range(steps):
            pp, vv = physics.integrate_rk4(pp, vv, a_const, dt)
        return pp, vv

    warmup(work_euler, rounds=1)
    warmup(work_rk4, rounds=1)

    # run both to store separate baselines
    be = benchmark(work_euler)
    br = benchmark(work_rk4)
    assert be and br

# -----------------------------
# CLI fallback (no pytest-benchmark)
# -----------------------------
def _cli():
    print("bench_physics (fallback mode, no pytest-benchmark)")
    parts = gen_particles(min(2000, N_PARTICLES))
    spheres = gen_spheres(min(1000, N_COLLISION))
    aabbs = gen_aabbs(min(1000, N_COLLISION))

    def bench(name, fn, it=1):
        dt = _manual_bench(fn, iters=it)
        print(f"{name:34s}  {dt*1e3:8.3f} ms/iter")

    # vec
    rnd = _rng()
    vecs = [v3(rnd.uniform(-1,1), rnd.uniform(-1,1), rnd.uniform(-1,1)) for _ in range(20000)]
    bench("vec.dot/length/normalize", lambda: sum(physics.dot(vecs[i], vecs[(i+1)%len(vecs)]) for i in range(0, len(vecs), 2)))

    # integrate Euler/RK4
    def integ(intg: str):
        dt = 1/120
        def step():
            for i in range(len(parts)):
                pi = parts[i]
                g = physics.gravity(pi.m, 9.80665)
                Fd = physics.drag(pi.v, 1.225, 1.0, pi.A)
                a = physics.add(physics.mul(g, 1.0/pi.m), physics.mul(Fd, 1.0/pi.m))
                if intg == "euler":
                    p2, v2 = physics.integrate_euler(pi.p, pi.v, a, dt)
                else:
                    p2, v2 = physics.integrate_rk4(pi.p, pi.v, a, dt)
                pi.p, pi.v = p2, v2
        return step
    bench("integrate_euler particles", integ("euler"), it=10)
    bench("integrate_rk4 particles", integ("rk4"), it=10)

    # collisions
    window = 32
    def sph():
        hit = 0
        for i in range(len(spheres)):
            p1, r1 = spheres[i]
            for j in range(i+1, min(len(spheres), i+1+window)):
                p2, r2 = spheres[j]
                res = physics.collide_spheres(p1, r1, p2, r2)
                hit += 1 if res["colliding"] else 0
        return hit
    bench("collide_spheres windowed", sph, it=1)

    def aabb():
        cnt = 0
        for i in range(len(aabbs)):
            a_min, a_max = aabbs[i]
            for j in range(i+1, min(len(aabbs), i+1+48)):
                b_min, b_max = aabbs[j]
                if physics.aabb_overlap(a_min, a_max, b_min, b_max):
                    cnt += 1
        return cnt
    bench("aabb_overlap windowed", aabb, it=1)

if __name__ == "__main__":
    # If launched directly, run fallback microbenchmarks
    _cli()
