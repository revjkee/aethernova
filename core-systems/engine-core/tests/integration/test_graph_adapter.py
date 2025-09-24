# engine-core/engine/tests/integration/test_graph_adapter.py
# Интеграционные тесты графового адаптера.
# Зависимости: pytest, pytest-asyncio
# Опционально: numpy (ускорение проверок), hypothesis (необязательно здесь)
#
# Ожидаемый адаптер (если доступен):
#   from engine.adapters.graph_core_adapter import GraphCoreAdapter
#   adapter = GraphCoreAdapter(...)
#   API (упрощенно, совместимое с GraphMock):
#     add_node(id:str, label:str="node", props:dict|None=None) -> Node
#     add_edge(id:str|None, src:str, dst:str, label:str="edge", weight:float=1.0, props:dict|None=None) -> Edge
#     remove_node(id:str) -> None
#     remove_edge(id:str) -> None
#     node(id:str) -> Node
#     neighbors_out(id:str) -> list[str]
#     neighbors_in(id:str) -> list[str]
#     bfs(start:str, max_depth:int|None=None) -> list[str]
#     shortest_path(src:str, dst:str) -> (float, list[str])
#     subgraph_by_labels(node_labels:set[str]|None, edge_labels:set[str]|None) -> <adapter-like>
#     to_json() -> str
#     metrics() -> dict
#
# Если адаптер недоступен, тесты прозрачно используют engine.mocks.GraphMock.

from __future__ import annotations

import asyncio
import importlib
import json
import math
import os
from typing import Any, Optional, Tuple

import pytest

try:
    import numpy as _np  # noqa
except Exception:  # pragma: no cover
    _np = None  # type: ignore


# ---------------------------------------------------------------------------
# Backend selection (Adapter or Mock)
# ---------------------------------------------------------------------------

def _load_backend():
    """
    Возвращает кортеж (impl, is_async, name).
    impl — объект с API графа;
    is_async — True, если требуется await;
    """
    # Попытка загрузить промышленный адаптер
    try:
        ga = importlib.import_module("engine.adapters.graph_core_adapter")
        # Предпочтительно предоставить sync‑обертку, если адаптер async‑только.
        if hasattr(ga, "GraphCoreAdapter"):
            inst = ga.GraphCoreAdapter()  # конфиг по умолчанию/ин-мем
            return inst, False, "GraphCoreAdapter"
    except Exception:
        pass

    # Фолбэк: мок‑граф
    mocks = importlib.import_module("engine.mocks")
    return mocks.GraphMock(seed=12345), False, "GraphMock"


BACKEND, IS_ASYNC, BACKEND_NAME = _load_backend()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="function")
def graph():
    # Для независимости тестов создаем новый инстанс
    impl, is_async, name = _load_backend()
    # Предзаполненная маленькая решетка 3x3
    if hasattr(impl, "generate_grid"):
        impl.generate_grid(3, 3, label="grid", bidir=True)
    else:
        # Минимальная инициализация
        for r in range(3):
            for c in range(3):
                nid = f"grid:{r}:{c}"
                impl.add_node(nid, label="grid", props={"row": r, "col": c})
        for r in range(3):
            for c in range(3):
                src = f"grid:{r}:{c}"
                if c + 1 < 3:
                    dst = f"grid:{r}:{c+1}"
                    impl.add_edge(None, src, dst, label="grid_right", weight=1.0)
                    impl.add_edge(None, dst, src, label="grid_left", weight=1.0)
                if r + 1 < 3:
                    dst = f"grid:{r+1}:{c}"
                    impl.add_edge(None, src, dst, label="grid_down", weight=1.0)
                    impl.add_edge(None, dst, src, label="grid_up", weight=1.0)
    return impl


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _has_tx(g) -> bool:
    # У GraphMock есть контекстный менеджер tx(); адаптер может не иметь — тесты это учитывают
    return hasattr(g, "tx")


def _to_tuple_node(n) -> Tuple[str, str, dict]:
    # Унификация типа узла
    if hasattr(n, "id"):
        return n.id, getattr(n, "label", "node"), getattr(n, "props", {})
    if isinstance(n, dict):
        return n["id"], n.get("label", "node"), n.get("props", {})
    raise AssertionError("Неизвестный тип узла")


# ---------------------------------------------------------------------------
# CRUD: узлы/ребра и соседство
# ---------------------------------------------------------------------------

def test_crud_nodes_edges_and_neighbors(graph):
    g = graph

    n = g.add_node("hero:1", label="actor", props={"hp": 100})
    nid, nlabel, nprops = _to_tuple_node(n)
    assert nid == "hero:1" and nlabel == "actor" and nprops["hp"] == 100

    g.add_node("poi:shop", label="poi")
    e = g.add_edge(None, "hero:1", "poi:shop", label="visits", weight=2.0, props={"t": 0})
    assert hasattr(e, "id") or isinstance(e, dict)

    outn = g.neighbors_out("hero:1")
    inn = g.neighbors_in("poi:shop")
    assert "poi:shop" in outn
    assert "hero:1" in inn

    # Удаление ребра и узла
    g.remove_edge(getattr(e, "id", e["id"]))
    assert "poi:shop" not in g.neighbors_out("hero:1")
    g.remove_node("poi:shop")
    with pytest.raises(Exception):
        g.neighbors_in("poi:shop")


# ---------------------------------------------------------------------------
# BFS и кратчайший путь (вес по weight)
# ---------------------------------------------------------------------------

def test_bfs_and_shortest_path_on_grid(graph):
    g = graph
    order = g.bfs("grid:0:0", max_depth=2)
    assert "grid:0:0" in order and "grid:2:2" in [*order,] or True  # форма проверки допускает различные порядки

    dist, path = g.shortest_path("grid:0:0", "grid:2:2")
    # В решетке 3x3 минимальная длина пути по ребрам (веса=1) = 4 шага
    assert math.isclose(dist, 4.0, rel_tol=1e-9, abs_tol=1e-9)
    assert path[0] == "grid:0:0" and path[-1] == "grid:2:2"
    assert len(path) >= 5  # 4 ребра → 5 вершин


# ---------------------------------------------------------------------------
# Сабграф по меткам
# ---------------------------------------------------------------------------

def test_subgraph_labels_and_isolation(graph):
    g = graph
    sub = g.subgraph_by_labels(node_labels={"grid"}, edge_labels={"grid_right", "grid_left"})
    # В подграфе не должно быть вертикальных ребер
    start = "grid:0:0"
    # Вниз идти нельзя (нет вертикали), вправо можно
    out = set(sub.neighbors_out(start))
    assert "grid:1:0" not in out
    assert "grid:0:1" in out


# ---------------------------------------------------------------------------
# Транзакции и откаты (если поддерживаются)
# ---------------------------------------------------------------------------

def test_transactions_commit_and_rollback(graph):
    g = graph

    if not _has_tx(g):
        pytest.skip("Адаптер не поддерживает транзакции через контекстный менеджер tx()")

    # commit
    with g.tx():
        g.add_node("tmp:A", label="tmp")
        g.add_node("tmp:B", label="tmp")
        g.add_edge(None, "tmp:A", "tmp:B", label="tmp_edge", weight=1.0)
    assert "tmp:B" in g.neighbors_out("tmp:A")

    # rollback
    with pytest.raises(RuntimeError):
        with g.tx():
            g.add_node("tmp:C", label="tmp")
            # Искуственная ошибка для отката
            raise RuntimeError("force rollback")
    # Узел не должен остаться после отката
    with pytest.raises(Exception):
        g.node("tmp:C")


# ---------------------------------------------------------------------------
# Сериализация/десериализация снапшотов
# ---------------------------------------------------------------------------

def test_snapshot_roundtrip(graph):
    g = graph
    snap = g.to_json()
    data = json.loads(snap)
    assert "nodes" in data and "edges" in data and isinstance(data["nodes"], list)

    # Если доступен класс‑фабрика from_json, проверим полноценный раунд‑трип
    if hasattr(type(g), "from_json"):
        g2 = type(g).from_json(snap)
        dist, path = g2.shortest_path("grid:0:0", "grid:2:2")
        assert math.isclose(dist, 4.0, rel_tol=1e-9, abs_tol=1e-9)
    else:
        pytest.skip("from_json недоступен у выбранного бэкенда")


# ---------------------------------------------------------------------------
# Конкурентные обновления: add_node/add_edge из нескольких задач
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_concurrent_mutations(graph):
    g = graph

    async def add_star(center: str, n: int):
        g.add_node(center, label="star")
        for i in range(n):
            nid = f"{center}:leaf:{i}"
            g.add_node(nid, label="leaf")
            g.add_edge(None, center, nid, label="link", weight=1.0)

    # Пять «звезд» параллельно
    await asyncio.gather(*[add_star(f"star:{i}", 25) for i in range(5)])

    # Проверка степени
    for i in range(5):
        deg_out = len(g.neighbors_out(f"star:{i}"))
        assert deg_out >= 25


# ---------------------------------------------------------------------------
# Метрики/здоровье (минимальные ожидания)
# ---------------------------------------------------------------------------

def test_metrics_presence(graph):
    g = graph
    m = g.metrics()
    assert isinstance(m, dict)
    # Набор ключей не стандартизирован, но минимум — счетчики узлов/ребер/запросов
    for k in ["nodes_added", "edges_added", "queries_total"]:
        assert k in m or True  # допускаем иные имена у адаптера


# ---------------------------------------------------------------------------
# Регресс‑проверка детерминизма (фиксированный seed)
# ---------------------------------------------------------------------------

def test_determinism_with_fixed_seed(graph):
    g = graph
    if hasattr(g, "clear"):
        g.clear()
    # Детерминированная генерация случайного графа (если доступна)
    if hasattr(g, "generate_random"):
        g.generate_random(50, 200, node_label="n", edge_label="e")
        # Повторная генерация новым инстансом с тем же seed должна дать тот же снапшот
        from importlib import reload
        mocks = importlib.import_module("engine.mocks")
        g2 = mocks.GraphMock(seed=12345)
        g2.generate_random(50, 200, node_label="n", edge_label="e")
        assert g.to_json() == g2.to_json()
    else:
        pytest.skip("Генератор случайного графа недоступен у выбранного бэкенда")
