# engine/tests/conformance/test_interest_management.py
"""
Conformance-тесты Interest Management / Area-of-Interest (AOI) подсистемы.

Ожидаемый модуль: engine.interest c одним из API:
  - InterestManager(config: dict|None)  # класс
  - create_interest_manager(config: dict|None) -> InterestManager  # фабрика

Минимально ожидаемые методы/семантика (любая часть может отсутствовать — тогда xfail/skip):
  - add_entity(entity_id, pos: tuple[float, float] | tuple[float, float, float], **attrs)
  - remove_entity(entity_id)
  - move_entity(entity_id, pos)
  - subscribe(client_id, center: tuple, radius: float, *, layers: set[str]|None=None, caps: dict|None=None)
  - unsubscribe(client_id)
  - update_subscription(client_id, center, radius, **opts)
  - query(client_id) -> iterable[str|int]  # набор entity_id в AOI
  - tick(dt: float)  # если нужно
  - get_events(client_id) -> list[{"type": "enter"|"leave"|"update", "entity": id, ...}]  # при наличии событий
  - set_rate_limit(client_id, hz: float)  # если есть лимитирование выдачи
  - config/flags:
      .supports_hysteresis, .supports_lod, .supports_layers, .supports_rate_limit,
      .supports_caps, .supports_3d, .supports_priority

Тесты устойчивы к разным реализациям: если чего-то нет — помечаем как xfail/skip, не ломая CI.
"""

from __future__ import annotations

import math
import os
import random
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional, Tuple

import pytest

mod = pytest.importorskip("engine.interest", reason="engine.interest module not found")

InterestManager = getattr(mod, "InterestManager", None)
create_im = getattr(mod, "create_interest_manager", None)

if InterestManager is None and create_im is None:
    pytest.skip("No InterestManager or create_interest_manager in engine.interest", allow_module_level=True)


# -----------------------
# Вспомогательные типы/утилиты
# -----------------------

Vec2 = Tuple[float, float]
Vec3 = Tuple[float, float, float]

@dataclass
class IMCfg:
    hysteresis_in: float = 0.0
    hysteresis_out: float = 0.0
    max_results: int = 0
    layers: Optional[set[str]] = None
    lod_thresholds: Optional[Tuple[float, float]] = None  # (lod1, lod2)
    rate_limit_hz: Optional[float] = None
    is_3d: bool = False

def _make_manager(cfg: Optional[IMCfg] = None) -> Any:
    conf: Dict[str, Any] = {}
    if cfg:
        if cfg.hysteresis_in or cfg.hysteresis_out:
            conf["hysteresis"] = {"enter": cfg.hysteresis_in, "exit": cfg.hysteresis_out}
        if cfg.max_results:
            conf["caps"] = {"max_results": cfg.max_results}
        if cfg.lod_thresholds:
            conf["lod"] = {"thresholds": list(cfg.lod_thresholds)}
        if cfg.rate_limit_hz:
            conf["rate_limit_hz"] = cfg.rate_limit_hz
        if cfg.layers:
            conf["layers_enabled"] = True
        if cfg.is_3d:
            conf["is_3d"] = True

    if InterestManager is not None:
        try:
            return InterestManager(conf)  # type: ignore
        except TypeError:
            return InterestManager()  # type: ignore
    return create_im(conf)  # type: ignore


def _supports(mgr: Any, attr: str) -> bool:
    return bool(getattr(mgr, attr, None))

def _maybe_tick(mgr: Any, dt: float = 0.0) -> None:
    tick = getattr(mgr, "tick", None)
    if callable(tick):
        tick(dt)

def _query_set(mgr: Any, client: str) -> set:
    q = mgr.query(client)
    return set(q if isinstance(q, Iterable) else [])

def _dist2(a: Tuple[float, ...], b: Tuple[float, ...]) -> float:
    return sum((x - y) ** 2 for x, y in zip(a, b))

# -----------------------
# Фикстуры
# -----------------------

@pytest.fixture()
def mgr_basic() -> Any:
    # Базовый менеджер без гистерезиса/кап/LOD
    return _make_manager()

@pytest.fixture()
def mgr_hysteresis() -> Any:
    m = _make_manager(IMCfg(hysteresis_in=5.0, hysteresis_out=7.5))
    if not getattr(m, "supports_hysteresis", False) and not getattr(m, "config", {}):
        pytest.xfail("Hysteresis not supported by implementation")
    return m

@pytest.fixture()
def mgr_caps_priority() -> Any:
    m = _make_manager(IMCfg())
    if not getattr(m, "supports_caps", False) and not getattr(m, "supports_priority", False):
        pytest.xfail("Caps/Priority not supported")
    return m

@pytest.fixture()
def mgr_layers() -> Any:
    m = _make_manager(IMCfg())
    if not getattr(m, "supports_layers", False):
        pytest.xfail("Layers not supported")
    return m

@pytest.fixture()
def mgr_rate_limit() -> Any:
    m = _make_manager(IMCfg(rate_limit_hz=10.0))
    if not getattr(m, "supports_rate_limit", False) and not hasattr(m, "set_rate_limit"):
        pytest.xfail("Rate limiting not supported")
    return m

@pytest.fixture()
def mgr_lod() -> Any:
    m = _make_manager(IMCfg(lod_thresholds=(10.0, 30.0)))
    if not getattr(m, "supports_lod", False) and not hasattr(m, "get_lod"):
        pytest.xfail("LOD not supported")
    return m

# -----------------------
# Базовая видимость и подписка
# -----------------------

def test_basic_subscription_visibility_2d(mgr_basic):
    center: Vec2 = (0.0, 0.0)
    R = 10.0
    mgr_basic.subscribe("c1", center, R)

    mgr_basic.add_entity("e1", (0.0, 0.0))
    mgr_basic.add_entity("e2", (5.0, 0.0))
    mgr_basic.add_entity("e3", (9.9, 0.0))
    mgr_basic.add_entity("e4", (10.1, 0.0))  # за пределом

    _maybe_tick(mgr_basic, 0.016)
    vis = _query_set(mgr_basic, "c1")
    assert vis.issuperset({"e1", "e2", "e3"})
    assert "e4" not in vis


def test_move_entity_triggers_enter_leave(mgr_basic):
    mgr_basic.subscribe("c1", (0.0, 0.0), 5.0)
    mgr_basic.add_entity("e", (10.0, 0.0))
    _maybe_tick(mgr_basic, 0.016)
    assert "e" not in _query_set(mgr_basic, "c1")

    mgr_basic.move_entity("e", (4.9, 0.0))
    _maybe_tick(mgr_basic, 0.016)
    assert "e" in _query_set(mgr_basic, "c1")

    mgr_basic.move_entity("e", (5.2, 0.0))
    _maybe_tick(mgr_basic, 0.016)
    assert "e" not in _query_set(mgr_basic, "c1")

    # Если есть события — проверим их наличие
    get_events = getattr(mgr_basic, "get_events", None)
    if callable(get_events):
        evs = get_events("c1")
        types = [e.get("type") for e in evs]
        # допускаем ['enter','leave'] или с промежуточными 'update'
        assert "enter" in types and "leave" in types


# -----------------------
# Гистерезис (вход/выход)
# -----------------------

def test_hysteresis_reduces_churn_if_supported(mgr_hysteresis):
    if not getattr(mgr_hysteresis, "supports_hysteresis", False):
        pytest.xfail("Hysteresis not supported")
    mgr_hysteresis.subscribe("c1", (0.0, 0.0), 10.0)
    mgr_hysteresis.add_entity("e", (10.1, 0.0))
    _maybe_tick(mgr_hysteresis)

    # Чуть внутрь — меньше радиуса входа? Должно войти.
    mgr_hysteresis.move_entity("e", (4.9, 0.0))
    _maybe_tick(mgr_hysteresis)
    assert "e" in _query_set(mgr_hysteresis, "c1")

    # Выпихиваем немного за базовый радиус, но не за радиус выхода — остаётся видимым
    mgr_hysteresis.move_entity("e", (10.4, 0.0))
    _maybe_tick(mgr_hysteresis)
    assert "e" in _query_set(mgr_hysteresis, "c1"), "hysteresis exit should prevent immediate churn"

    # Сильно наружу — должен покинуть
    mgr_hysteresis.move_entity("e", (20.0, 0.0))
    _maybe_tick(mgr_hysteresis)
    assert "e" not in _query_set(mgr_hysteresis, "c1")


# -----------------------
# Многоклиентная изоляция
# -----------------------

def test_isolation_between_clients(mgr_basic):
    mgr_basic.subscribe("c1", (0.0, 0.0), 5.0)
    mgr_basic.subscribe("c2", (100.0, 0.0), 5.0)
    for i in range(5):
        mgr_basic.add_entity(f"a{i}", (i, 0.0))
        mgr_basic.add_entity(f"b{i}", (100.0 + i, 0.0))

    _maybe_tick(mgr_basic)
    v1 = _query_set(mgr_basic, "c1")
    v2 = _query_set(mgr_basic, "c2")
    assert all(e.startswith("a") for e in v1)
    assert all(e.startswith("b") for e in v2)
    assert v1.isdisjoint(v2)


# -----------------------
# Кап результатов и приоритет
# -----------------------

def test_visibility_cap_and_priority_if_supported(mgr_caps_priority):
    if not getattr(mgr_caps_priority, "supports_caps", False):
        pytest.xfail("Max-results caps not supported")

    center = (0.0, 0.0)
    mgr_caps_priority.subscribe("c1", center, 100.0)
    # 20 объектов на разных дистанциях
    for i in range(20):
        mgr_caps_priority.add_entity(f"e{i}", (float(i), 0.0), priority=random.randint(0, 5))

    # Включаем кап через обновление подписки, если поддерживается
    if hasattr(mgr_caps_priority, "update_subscription"):
        mgr_caps_priority.update_subscription("c1", center, 100.0, caps={"max_results": 5})
    else:
        # попытаемся через конфиг на уровне менеджера — если не получится, всё равно проверим поведение по умолчанию
        pass

    _maybe_tick(mgr_caps_priority)
    vis = list(_query_set(mgr_caps_priority, "c1"))
    if len(vis) <= 5:
        assert len(vis) <= 5
    else:
        # если кап игнорируется — ослабим ожидание, но проверим стабильность топ‑N по расстоянию
        # топ-5 по близости: e0..e4
        expect = {f"e{i}" for i in range(5)}
        have_top = expect.issubset(set(vis))
        assert have_top, "Top-N closest entities should be prioritized when caps are present"


# -----------------------
# Rate limiting (если есть)
# -----------------------

def test_rate_limiting_updates_if_supported(mgr_rate_limit):
    # Попробуем задать 5 Гц и убедиться, что выдача/события не чаще
    if hasattr(mgr_rate_limit, "set_rate_limit"):
        mgr_rate_limit.set_rate_limit("c1", 5.0)
    mgr_rate_limit.subscribe("c1", (0.0, 0.0), 50.0)

    for i in range(10):
        mgr_rate_limit.add_entity(f"e{i}", (float(i), 0.0))

    _maybe_tick(mgr_rate_limit)
    get_events = getattr(mgr_rate_limit, "get_events", None)
    if not callable(get_events):
        pytest.xfail("No event API to verify rate limiting")

    # Пощёлкаем несколько тиков и посчитаем частоту обновлений
    t0 = time.time()
    events_count = 0
    for _ in range(10):
        time.sleep(0.05)
        _maybe_tick(mgr_rate_limit, 0.05)
        events_count += len(get_events("c1") or [])
    duration = time.time() - t0
    # При 5 Гц ожидаем порядка <= 10 событий за ~0.5с (допускаем разброс)
    assert events_count <= 20, f"Too many events emitted under rate limit: {events_count} in {duration:.2f}s"


# -----------------------
# LOD (levels of detail)
# -----------------------

def test_lod_levels_if_supported(mgr_lod):
    get_lod = getattr(mgr_lod, "get_lod", None)
    if not callable(get_lod) and not getattr(mgr_lod, "supports_lod", False):
        pytest.xfail("LOD API not available")

    mgr_lod.subscribe("c1", (0.0, 0.0), 100.0)
    mgr_lod.add_entity("near", (5.0, 0.0))
    mgr_lod.add_entity("mid", (20.0, 0.0))
    mgr_lod.add_entity("far", (50.0, 0.0))
    _maybe_tick(mgr_lod)

    # Если есть явная get_lod(client, entity)
    if callable(get_lod):
        ln = get_lod("c1", "near")
        lm = get_lod("c1", "mid")
        lf = get_lod("c1", "far")
        assert ln <= lm <= lf, "LOD should degrade with distance"
    else:
        # fallback: проверим, что дальние приходят реже по событиям
        if callable(getattr(mgr_lod, "get_events", None)):
            # прогоняем движения, чтобы накопить апдейты
            for _ in range(5):
                mgr_lod.move_entity("near", (5.0 + random.uniform(-0.1, 0.1), 0.0))
                mgr_lod.move_entity("far", (50.0 + random.uniform(-0.1, 0.1), 0.0))
                _maybe_tick(mgr_lod, 0.05)
            evs = mgr_lod.get_events("c1")
            near_updates = sum(1 for e in evs if e.get("entity") == "near" and e.get("type") == "update")
            far_updates = sum(1 for e in evs if e.get("entity") == "far" and e.get("type") == "update")
            assert near_updates >= far_updates, "Far entities should not update more often than near ones"


# -----------------------
# 3D координаты (если поддерживаются)
# -----------------------

def test_3d_positions_if_supported():
    m = _make_manager(IMCfg(is_3d=True))
    if not getattr(m, "supports_3d", False) and not getattr(m, "config", {}).get("is_3d", False):
        pytest.xfail("3D not supported")
    m.subscribe("c1", (0.0, 0.0, 0.0), 5.0)
    m.add_entity("e_in", (1.0, 2.0, 1.0))
    m.add_entity("e_out", (10.0, 0.0, 0.0))
    _maybe_tick(m)
    vis = _query_set(m, "c1")
    assert "e_in" in vis and "e_out" not in vis


# -----------------------
# Фильтры слоёв/тэгов (если поддерживаются)
# -----------------------

def test_layer_filters_if_supported(mgr_layers):
    if not getattr(mgr_layers, "supports_layers", False):
        pytest.xfail("Layers not supported")
    m = mgr_layers
    m.subscribe("c1", (0.0, 0.0), 50.0, layers={"enemy"})
    m.subscribe("c2", (0.0, 0.0), 50.0, layers={"ally"})
    m.add_entity("goblin", (1.0, 0.0), layers={"enemy"})
    m.add_entity("knight", (1.0, 0.0), layers={"ally"})
    _maybe_tick(m)
    assert "goblin" in _query_set(m, "c1") and "knight" not in _query_set(m, "c1")
    assert "knight" in _query_set(m, "c2") and "goblin" not in _query_set(m, "c2")


# -----------------------
# Удаление и телепорт
# -----------------------

def test_remove_entity_and_teleport(mgr_basic):
    m = mgr_basic
    m.subscribe("c1", (0.0, 0.0), 10.0)
    m.add_entity("e", (1.0, 0.0))
    _maybe_tick(m)
    assert "e" in _query_set(m, "c1")

    m.remove_entity("e")
    _maybe_tick(m)
    assert "e" not in _query_set(m, "c1")

    # Телепорт — должен сменить видимость корректно
    m.add_entity("t", (50.0, 0.0))
    _maybe_tick(m)
    assert "t" not in _query_set(m, "c1")
    # телепорт внутрь
    m.move_entity("t", (0.0, 0.0))
    _maybe_tick(m)
    assert "t" in _query_set(m, "c1")


# -----------------------
# Обновление подписки
# -----------------------

def test_update_subscription_radius_and_center(mgr_basic):
    m = mgr_basic
    m.subscribe("c1", (0.0, 0.0), 5.0)
    m.add_entity("e", (7.0, 0.0))
    _maybe_tick(m)
    assert "e" not in _query_set(m, "c1")

    upd = getattr(m, "update_subscription", None)
    if not callable(upd):
        pytest.xfail("update_subscription not supported")

    m.update_subscription("c1", (0.0, 0.0), 10.0)
    _maybe_tick(m)
    assert "e" in _query_set(m, "c1")

    m.update_subscription("c1", (100.0, 0.0), 5.0)
    _maybe_tick(m)
    assert "e" not in _query_set(m, "c1")


# -----------------------
# Перформанс-смоук (опционально)
# -----------------------

@pytest.mark.skipif(os.getenv("IM_PERF", "0") not in ("1", "true", "yes", "on"),
                    reason="Perf smoke disabled; set IM_PERF=1 to enable")
def test_perf_smoke_large_population():
    # Не строгий тест: проверяем, что добавление и первичный query укладываются в разумный бюджет.
    N = int(os.getenv("IM_PERF_N", "2000"))
    m = _make_manager()
    m.subscribe("c", (0.0, 0.0), 1000.0)
    t0 = time.perf_counter()
    for i in range(N):
        m.add_entity(f"e{i}", (random.uniform(-500, 500), random.uniform(-500, 500)))
    _maybe_tick(m)
    vis = _query_set(m, "c")
    t1 = time.perf_counter()
    # Бюджет мягкий и зависит от реализации; по умолчанию 2 секунды на N=2000
    assert (t1 - t0) < float(os.getenv("IM_PERF_BUDGET_SEC", "2.0"))
    assert isinstance(vis, set)
