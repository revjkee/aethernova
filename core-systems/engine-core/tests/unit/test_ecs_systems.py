# engine-core/engine/tests/unit/test_ecs_systems.py
# -*- coding: utf-8 -*-
"""
Контрактные и детерминизационные тесты для ECS подсистем движка.

Покрывает:
- MovementSystem: интеграция положения, лимит скорости, трение, dt=0, детерминизм
- InterestManagement: корректность фильтра по радиусу/ячейкам, детерминизм
- Pathfinding: путь на решётке с препятствием, монотонность стоимости
- Determinism.Lockstep: стабильность хэша тика при равных входах

Тесты спроектированы так, чтобы безопасно "пропускать" отсутствующие модули
(используются importorskip/xfail) и одновременно служить спецификацией API.
"""

from __future__ import annotations

import math
import random
import hashlib
from dataclasses import dataclass, field
from typing import Dict, Tuple, List, Any, Iterable, Optional

import pytest

# ============================================================
# Утилиты и фейки мира/сущностей
# ============================================================

Vec2 = Tuple[float, float]

def v_add(a: Vec2, b: Vec2) -> Vec2:
    return (a[0] + b[0], a[1] + b[1])

def v_scale(a: Vec2, k: float) -> Vec2:
    return (a[0] * k, a[1] * k)

def v_len(a: Vec2) -> float:
    return math.hypot(a[0], a[1])

def approx(a: float, b: float, eps: float = 1e-6) -> bool:
    return abs(a - b) <= eps

@dataclass
class Transform:
    x: float
    y: float

@dataclass
class PhysicsBody:
    vx: float
    vy: float
    max_speed: float = 10.0
    friction: float = 0.0  # коэффициент [0..1] на шаг

@dataclass
class Entity:
    id: int
    transform: Transform
    body: Optional[PhysicsBody] = None
    tags: Dict[str, Any] = field(default_factory=dict)

class FakeWorld:
    def __init__(self) -> None:
        self.entities: Dict[int, Entity] = {}

    def add(self, e: Entity) -> None:
        self.entities[e.id] = e

    def find_with_body(self) -> Iterable[Entity]:
        return (e for e in self.entities.values() if e.body is not None)

# ============================================================
# MovementSystem контракты
# ============================================================

@pytest.fixture
def movement_mod():
    return pytest.importorskip("engine.engine.ecs.systems.movement_system", reason="movement_system отсутствует")

def _ref_step(body: PhysicsBody, tr: Transform, dt: float) -> None:
    """Опорная (референсная) интеграция для проверки детерминизма/лимитов."""
    if dt <= 0.0:
        return
    # трение: затухание скорости
    if body.friction > 0.0:
        k = max(0.0, 1.0 - body.friction)
        body.vx *= k
        body.vy *= k
    # лимит скорости
    speed = math.hypot(body.vx, body.vy)
    if speed > body.max_speed > 0.0:
        s = body.max_speed / speed
        body.vx *= s
        body.vy *= s
    # интеграция
    tr.x += body.vx * dt
    tr.y += body.vy * dt

def _mk_world_for_move(n: int = 10) -> FakeWorld:
    rnd = random.Random(12345)
    w = FakeWorld()
    for i in range(n):
        vx, vy = rnd.uniform(-5, 5), rnd.uniform(-5, 5)
        e = Entity(
            id=i + 1,
            transform=Transform(x=rnd.uniform(-10, 10), y=rnd.uniform(-10, 10)),
            body=PhysicsBody(vx=vx, vy=vy, max_speed=6.0, friction=0.05),
        )
        w.add(e)
    return w

def _state_digest(world: FakeWorld) -> str:
    # детерминизм: фиксируем порядок по id
    parts: List[str] = []
    for eid in sorted(world.entities.keys()):
        e = world.entities[eid]
        if e.body:
            parts.append(f"{eid}:{e.transform.x:.6f},{e.transform.y:.6f}|{e.body.vx:.6f},{e.body.vy:.6f}")
        else:
            parts.append(f"{eid}:{e.transform.x:.6f},{e.transform.y:.6f}")
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()

def test_movement_dt_zero_no_change(movement_mod):
    MovementSystem = getattr(movement_mod, "MovementSystem", None)
    if MovementSystem is None:
        pytest.xfail("MovementSystem не найден")
    world = _mk_world_for_move(3)
    sys = MovementSystem()
    before = _state_digest(world)
    sys.step(world, dt=0.0)
    after = _state_digest(world)
    assert before == after, "При dt=0 состояние не должно меняться"

def test_movement_speed_limit_and_friction(movement_mod):
    MovementSystem = getattr(movement_mod, "MovementSystem", None)
    if MovementSystem is None:
        pytest.xfail("MovementSystem не найден")
    w = FakeWorld()
    e = Entity(1, Transform(0.0, 0.0), PhysicsBody(vx=100.0, vy=0.0, max_speed=5.0, friction=0.2))
    w.add(e)
    sys = MovementSystem()
    sys.step(w, dt=1.0)
    # Проверка: скорость ограничена и уменьшена трением
    speed = math.hypot(e.body.vx, e.body.vy)
    assert speed <= 5.0 + 1e-6
    # Позиция сместилась не более 5 ед.
    assert e.transform.x <= 5.0 + 1e-6
    # Повторный шаг — скорость убывает монотонно из-за трения
    v1 = math.hypot(e.body.vx, e.body.vy)
    sys.step(w, dt=1.0)
    v2 = math.hypot(e.body.vx, e.body.vy)
    assert v2 <= v1 + 1e-9

def test_movement_deterministic_digest(movement_mod):
    MovementSystem = getattr(movement_mod, "MovementSystem", None)
    if MovementSystem is None:
        pytest.xfail("MovementSystem не найден")
    sys = MovementSystem()
    w1 = _mk_world_for_move(12)
    w2 = _mk_world_for_move(12)
    dt_series = [0.016, 0.016, 0.010, 0.020, 0.033, 0.005]
    for dt in dt_series:
        sys.step(w1, dt=dt)
        sys.step(w2, dt=dt)
    assert _state_digest(w1) == _state_digest(w2), "Детерминизм нарушен при идентичных входах"

def test_movement_matches_reference_integration(movement_mod):
    MovementSystem = getattr(movement_mod, "MovementSystem", None)
    if MovementSystem is None:
        pytest.xfail("MovementSystem не найден")
    sys = MovementSystem()
    w_ref = _mk_world_for_move(8)
    w_sut = _mk_world_for_move(8)
    series = [0.02] * 50
    for dt in series:
        # референс
        for e in w_ref.find_with_body():
            _ref_step(e.body, e.transform, dt)
        # тестируемая система
        sys.step(w_sut, dt=dt)
    assert _state_digest(w_ref) == _state_digest(w_sut), "Интеграция не соответствует спецификации"

# ============================================================
# Interest Management контракты
# ============================================================

@pytest.fixture
def interest_mod():
    return pytest.importorskip("engine.engine.ecs.systems.interest_management", reason="interest_management отсутствует")

def test_interest_radius_filter(interest_mod):
    # Ожидаемый API: compute_interest(viewer_pos: (x,y), entities: Iterable[(id,pos)], radius: float) -> Set[id]
    compute_interest = getattr(interest_mod, "compute_interest", None)
    if compute_interest is None:
        pytest.xfail("compute_interest не найден")
    viewer = (0.0, 0.0)
    ents = [(1, (0.0, 3.0)), (2, (4.0, 0.0)), (3, (5.1, 0.0)), (4, (0.0, -4.9))]
    ids = compute_interest(viewer, ents, radius=5.0)
    assert set(ids) == {1, 2, 4}
    # Детерминизм: перестановка входа не влияет
    ents_rev = list(reversed(ents))
    ids2 = compute_interest(viewer, ents_rev, radius=5.0)
    assert set(ids2) == {1, 2, 4}

# ============================================================
# Pathfinding контракты
# ============================================================

@pytest.fixture
def pathfinding_mod():
    return pytest.importorskip("engine.engine.spatial.pathfinding", reason="pathfinding отсутствует")

def test_pathfinding_grid_with_obstacle(pathfinding_mod):
    # Ожидаемый API: shortest_path(grid, start, goal) -> list[(x,z)] или [] если нет пути
    shortest_path = getattr(pathfinding_mod, "shortest_path", None)
    if shortest_path is None:
        pytest.xfail("shortest_path не найден")
    # 0 = проходимо, 1 = препятствие
    grid = [
        [0,0,0,0,0],
        [0,1,1,1,0],
        [0,0,0,1,0],
        [0,1,0,0,0],
        [0,0,0,0,0],
    ]
    path = shortest_path(grid, (0,0), (4,4))
    assert path, "Путь должен существовать"
    # путь начинается и заканчивается корректно
    assert path[0] == (0,0) and path[-1] == (4,4)
    # клетки пути проходимы
    for x,z in path:
        assert grid[z][x] == 0

# ============================================================
# Lockstep/Determinism контракты
# ============================================================

@pytest.fixture
def lockstep_mod():
    return pytest.importorskip("engine.engine.determinism.lockstep", reason="lockstep отсутствует")

def test_lockstep_tick_hash_stable(lockstep_mod):
    # Ожидаемый API: tick_hash(state_bytes: bytes) -> str(hex) или int
    tick_hash = getattr(lockstep_mod, "tick_hash", None)
    if tick_hash is None:
        pytest.xfail("tick_hash не найден")
    s1 = b'{"players":[{"id":1,"x":1.0,"y":2.0}],"tick":100}'
    s2 = b'{"players":[{"id":1,"x":1.0,"y":2.0}],"tick":100}'
    h1 = str(tick_hash(s1))
    h2 = str(tick_hash(s2))
    assert h1 == h2
    # Малая правка должна менять хэш
    s3 = b'{"players":[{"id":1,"x":1.0,"y":2.1}],"tick":100}'
    h3 = str(tick_hash(s3))
    assert h1 != h3

# ============================================================
# Snapshot provider (опционально) — круговая проверка
# ============================================================

@pytest.fixture
def snapshot_mod():
    return pytest.importorskip("engine.engine.state.snapshot", reason="snapshot provider отсутствует")

def test_snapshot_provider_returns_mapping(snapshot_mod):
    # Ожидаемый API: StateProvider().get_state() -> Mapping
    StateProvider = getattr(snapshot_mod, "StateProvider", None)
    if StateProvider is None:
        pytest.xfail("StateProvider не найден")
    prov = StateProvider()
    state = prov.get_state()
    if hasattr(state, "__await__"):
        # допускаем корутину
        import asyncio
        state = asyncio.get_event_loop().run_until_complete(state)
    assert isinstance(state, dict), "Провайдер снапшота должен возвращать Mapping"

# ============================================================
# Маркеры производительности (легкая проверка времени)
# ============================================================

@pytest.mark.parametrize("n", [100, 1000])
def test_movement_perf_sanity(movement_mod, n, benchmark: Any = None):
    MovementSystem = getattr(movement_mod, "MovementSystem", None)
    if MovementSystem is None:
        pytest.xfail("MovementSystem не найден")
    world = _mk_world_for_move(n)
    sys = MovementSystem()
    def _run():
        sys.step(world, dt=0.016)
    # если установлен pytest-benchmark — используем, иначе просто вызов
    if benchmark is not None:
        benchmark(_run)
    else:
        _run()
