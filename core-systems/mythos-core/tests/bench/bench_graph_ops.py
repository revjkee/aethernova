# mythos-core/tests/bench/bench_graph_ops.py
# -*- coding: utf-8 -*-
"""
Промышленный бенчмарк графовых операций для mythos-core.

ОЖИДАЕМЫЙ ПУБЛИЧНЫЙ API (адаптеры внизу аккуратно скипают, если чего-то нет):
- mythos_core.graph.core:
    Graph [и/или] DiGraph
      .add_node(node, **attrs)
      .add_edge(u, v, **attrs)
      .neighbors(u) -> Iterable
      .nodes() -> Iterable
      .edges() -> Iterable[tuple[u,v]]
      .copy() -> Graph
      .subgraph(nodes: Iterable) -> Graph           [если нет — будет skip]
      .to_json() -> str                             [если нет — будет skip]
      .from_json(data: str) -> Graph (classmethod)  [если нет — будет skip]
      .bfs(start) -> Iterable                       [если нет — fallback BFS через neighbors]
      .dfs(start) -> Iterable                       [если нет — fallback DFS через neighbors]
      .shortest_path(u, v) -> list                  [если нет — fallback BFS-путь]
      .topological_sort() -> list                   [если нет — skip]
      .scc() -> list[set]                           [если нет — skip]

Переменные окружения:
- MYTHOS_BENCH_SCALE = tiny | small | medium | large  (по умолчанию: small)
- MYTHOS_BENCH_SEED  = целое число, по умолчанию 1337

Если установлен плагин pytest-benchmark — используется его fixture `benchmark`.
Если нет — включается резервный таймер на perf_counter с разогревом.

Метрики:
- время (сек) каждой операции на синтетических графах;
- оценка расхода памяти при построении (tracemalloc, если доступен).

Запуск:
    pytest -q tests/bench/bench_graph_ops.py
    MYTHOS_BENCH_SCALE=medium pytest -q tests/bench/bench_graph_ops.py
"""

from __future__ import annotations

import json
import os
import random
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Optional, Tuple

import pytest

try:
    import tracemalloc
    _TRACEMALLOC = True
except Exception:
    _TRACEMALLOC = False

# -----------------------
# Конфиг масштабов нагрузки
# -----------------------

@dataclass(frozen=True)
class Scale:
    nodes: int
    edges: int


_SCALES = {
    "tiny":   Scale(nodes=300,   edges=900),
    "small":  Scale(nodes=1_000, edges=3_000),
    "medium": Scale(nodes=5_000, edges=20_000),
    "large":  Scale(nodes=20_000, edges=120_000),
}

def _env_scale() -> Scale:
    name = os.getenv("MYTHOS_BENCH_SCALE", "small").lower().strip()
    return _SCALES.get(name, _SCALES["small"])

def _env_seed() -> int:
    try:
        return int(os.getenv("MYTHOS_BENCH_SEED", "1337"))
    except ValueError:
        return 1337


# -----------------------
# Импорт целевого графового API (аккуратно)
# -----------------------

_graph_mod = pytest.importorskip(
    "mythos_core.graph.core",
    reason="Требуется mythos_core.graph.core с Graph/DiGraph"
)

Graph = getattr(_graph_mod, "Graph", None)
DiGraph = getattr(_graph_mod, "DiGraph", None)

if Graph is None and DiGraph is None:
    pytest.skip("Не найдены Graph/DiGraph в mythos_core.graph.core", allow_module_level=True)


def _make_graph(directed: bool = True):
    """
    Пытаемся создать направленный граф. Предпочтительно DiGraph.
    Если только Graph доступен — пробуем без/с directed kwarg.
    """
    cls = DiGraph or Graph
    try:
        return cls()
    except TypeError:
        try:
            return cls(directed=directed)
        except TypeError:
            return cls()


def _has(obj, name: str) -> bool:
    return hasattr(obj, name) and callable(getattr(obj, name))


# -----------------------
# Резервный бенч-таймер (если нет pytest-benchmark)
# -----------------------

@pytest.fixture
def bench_timer():
    """
    Унифицированный интерфейс:
        bench_timer(callable, *args, warmup=3, repeat=10, min_time=0.2)
    Возвращает минимальное измеренное время одной итерации.
    Если есть pytest-benchmark — делегируем ему.
    """
    class _Adapter:
        def __init__(self, request):
            self._benchmark = request.config.pluginmanager.getplugin("benchmark")

        def __call__(self, fn: Callable, *args, warmup: int = 3, repeat: int = 10, min_time: float = 0.2, **kwargs) -> float:
            bm_fixture = None
            try:
                bm_fixture = pytest.request.getfixturevalue("benchmark")  # type: ignore[attr-defined]
            except Exception:
                bm_fixture = None

            if bm_fixture is not None:
                # Используем pytest-benchmark: он сам прогреет и измерит.
                result = bm_fixture(lambda: fn(*args, **kwargs))
                # Фикстура benchmark возвращает объект; нам достаточно вернуть секунды на итерацию.
                # Но API нестабилен, поэтому просто возвращаем 0.0 (метрика будет в отчёте плагина).
                return 0.0

            # Ручной режим
            # Прогрев
            for _ in range(max(0, warmup)):
                fn(*args, **kwargs)

            # Повторы до достижения min_time
            best = float("inf")
            total = 0.0
            runs = 0
            while runs < repeat or total < min_time:
                t0 = time.perf_counter()
                fn(*args, **kwargs)
                dt = time.perf_counter() - t0
                total += dt
                runs += 1
                if dt < best:
                    best = dt
                if runs >= 1000:  # предохранитель
                    break
            return best

    return _Adapter(pytest)


# -----------------------
# Генераторы графов
# -----------------------

def _gen_random_edges(n: int, m: int, seed: int, dag: bool) -> Iterable[Tuple[int, int]]:
    rnd = random.Random(seed)
    seen = set()
    if dag:
        # Генерируем ориентированный ацикличный граф: ребра i -> j, где i < j
        while len(seen) < m:
            u = rnd.randrange(0, n - 1)
            v = rnd.randrange(u + 1, n)
            if u != v:
                e = (u, v)
                if e not in seen:
                    seen.add(e)
        return seen
    else:
        while len(seen) < m:
            u = rnd.randrange(0, n)
            v = rnd.randrange(0, n)
            if u == v:
                continue
            e = (u, v)
            if e not in seen:
                seen.add(e)
        return seen


def _build_graph(n: int, m: int, seed: int, dag: bool) -> object:
    G = _make_graph(directed=True)
    # add_node может быть опционален; большинство реализаций допускают add_edge с несуществующими узлами.
    if _has(G, "add_node"):
        for i in range(n):
            G.add_node(i)
    for (u, v) in _gen_random_edges(n, m, seed, dag):
        G.add_edge(u, v)
    return G


# -----------------------
# Утилиты операций (с fallback там, где это безопасно)
# -----------------------

def _neighbors(G, u):
    if not _has(G, "neighbors"):
        pytest.skip("neighbors() недоступен")
    return list(G.neighbors(u))

def _bfs(G, start):
    if _has(G, "bfs"):
        return list(G.bfs(start))
    # fallback
    from collections import deque
    seen = {start}
    q = deque([start])
    order = []
    while q:
        u = q.popleft()
        order.append(u)
        for v in _neighbors(G, u):
            if v not in seen:
                seen.add(v)
                q.append(v)
    return order

def _dfs(G, start):
    if _has(G, "dfs"):
        return list(G.dfs(start))
    # fallback
    seen = set()
    stack = [start]
    order = []
    while stack:
        u = stack.pop()
        if u in seen:
            continue
        seen.add(u)
        order.append(u)
        nbrs = list(_neighbors(G, u))
        stack.extend(reversed(nbrs))
    return order

def _shortest_path(G, s, t):
    if _has(G, "shortest_path"):
        return G.shortest_path(s, t)
    # fallback: не взвешенный BFS путь
    from collections import deque
    prev = {s: None}
    q = deque([s])
    found = False
    while q and not found:
        u = q.popleft()
        for v in _neighbors(G, u):
            if v not in prev:
                prev[v] = u
                if v == t:
                    found = True
                    break
                q.append(v)
    if not found:
        return None
    # восстановление пути
    cur, path = t, []
    while cur is not None:
        path.append(cur)
        cur = prev[cur]
    return list(reversed(path))

def _topo_sort_or_skip(G):
    if not _has(G, "topological_sort"):
        pytest.skip("topological_sort() недоступен")
    return G.topological_sort()

def _scc_or_skip(G):
    if not _has(G, "scc"):
        pytest.skip("scc() недоступен")
    return G.scc()

def _copy_or_skip(G):
    if not _has(G, "copy"):
        pytest.skip("copy() недоступен")
    return G.copy()

def _subgraph_or_skip(G, nodes):
    if not _has(G, "subgraph"):
        pytest.skip("subgraph() недоступен")
    return G.subgraph(nodes)

def _to_json_or_skip(G):
    if not _has(G, "to_json"):
        pytest.skip("to_json() недоступен")
    return G.to_json()

def _from_json_or_skip(G_cls_module, data: str):
    # Ищем статический/классовый from_json либо функцию в модуле
    if hasattr(G_cls_module, "from_json") and callable(getattr(G_cls_module, "from_json")):
        return G_cls_module.from_json(data)  # type: ignore[attr-defined]
    if hasattr(G, "from_json") and callable(getattr(G, "from_json")):  # type: ignore[name-defined]
        return getattr(G, "from_json")(data)  # type: ignore[attr-defined]
    pytest.skip("from_json() недоступен")


# -----------------------
# Фикстуры
# -----------------------

@pytest.fixture(scope="module")
def scale() -> Scale:
    return _env_scale()

@pytest.fixture(scope="module")
def seed() -> int:
    return _env_seed()

@pytest.fixture(scope="module")
def dag_graph(scale: Scale, seed: int):
    return _build_graph(scale.nodes, scale.edges, seed, dag=True)

@pytest.fixture(scope="module")
def gen_graph(scale: Scale, seed: int):
    return _build_graph(scale.nodes, scale.edges, seed, dag=False)

@pytest.fixture(scope="module")
def any_node(scale: Scale) -> int:
    # Всегда валидный id узла из диапазона
    return 0

@pytest.fixture(scope="module")
def another_node(scale: Scale) -> int:
    return min(1, max(1, scale.nodes - 1))


# -----------------------
# Бенчмарки построения и памяти
# -----------------------

def test_bench_build_dag(bench_timer, scale: Scale, seed: int):
    def _build():
        _ = _build_graph(scale.nodes, scale.edges, seed, dag=True)
    t = bench_timer(_build)
    assert t >= 0.0  # фиксация, чтобы PyTest не ругался на «пустой» тест

def test_bench_build_general(bench_timer, scale: Scale, seed: int):
    def _build():
        _ = _build_graph(scale.nodes, scale.edges, seed, dag=False)
    t = bench_timer(_build)
    assert t >= 0.0

@pytest.mark.skipif(not _TRACEMALLOC, reason="tracemalloc недоступен")
def test_memory_build_general(scale: Scale, seed: int):
    tracemalloc.start()
    _ = _build_graph(scale.nodes, scale.edges, seed, dag=False)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    # Проверка на «не ноль», конкретные лимиты не фиксируем (зависят от реализации)
    assert peak > 0


# -----------------------
# Бенчмарки операций на DAG
# -----------------------

def test_bench_topo_sort_on_dag(bench_timer, dag_graph):
    def _run():
        order = _topo_sort_or_skip(dag_graph)
        # минимальная валидация: порядок не пуст
        assert isinstance(order, (list, tuple)) and len(order) > 0
    t = bench_timer(_run)
    assert t >= 0.0

def test_bench_bfs_on_dag(bench_timer, dag_graph, any_node: int):
    def _run():
        order = _bfs(dag_graph, any_node)
        assert len(order) >= 1
    t = bench_timer(_run)
    assert t >= 0.0

def test_bench_dfs_on_dag(bench_timer, dag_graph, any_node: int):
    def _run():
        order = _dfs(dag_graph, any_node)
        assert len(order) >= 1
    t = bench_timer(_run)
    assert t >= 0.0


# -----------------------
# Бенчмарки операций на общем графе
# -----------------------

def test_bench_bfs_on_general(bench_timer, gen_graph, any_node: int):
    def _run():
        order = _bfs(gen_graph, any_node)
        assert len(order) >= 1
    t = bench_timer(_run)
    assert t >= 0.0

def test_bench_dfs_on_general(bench_timer, gen_graph, any_node: int):
    def _run():
        order = _dfs(gen_graph, any_node)
        assert len(order) >= 1
    t = bench_timer(_run)
    assert t >= 0.0

def test_bench_shortest_path_general(bench_timer, gen_graph, any_node: int, another_node: int):
    def _run():
        _ = _shortest_path(gen_graph, any_node, another_node)  # путь может отсутствовать — это нормально
    t = bench_timer(_run)
    assert t >= 0.0

def test_bench_scc_general(bench_timer, gen_graph):
    def _run():
        comp = _scc_or_skip(gen_graph)
        assert isinstance(comp, (list, tuple))
    t = bench_timer(_run)
    assert t >= 0.0


# -----------------------
# Бенчмарки операций над структурой
# -----------------------

def test_bench_copy(bench_timer, gen_graph):
    def _run():
        G2 = _copy_or_skip(gen_graph)
        # слабая проверка идентичности числа узлов
        assert len(list(G2.nodes())) == len(list(gen_graph.nodes()))
    t = bench_timer(_run)
    assert t >= 0.0

def test_bench_subgraph(bench_timer, gen_graph, scale: Scale):
    sample = list(range(min( max(1, scale.nodes // 10), scale.nodes )))
    def _run():
        SG = _subgraph_or_skip(gen_graph, sample)
        assert len(list(SG.nodes())) == len(sample)
    t = bench_timer(_run)
    assert t >= 0.0


# -----------------------
# Бенчмарки сериализации
# -----------------------

def test_bench_serialize(bench_timer, gen_graph):
    def _run():
        s = _to_json_or_skip(gen_graph)
        # корректный JSON
        json.loads(s)
    t = bench_timer(_run)
    assert t >= 0.0

def test_bench_deserialize(bench_timer, gen_graph):
    data = _to_json_or_skip(gen_graph)
    def _run():
        G2 = _from_json_or_skip(_graph_mod, data)
        assert len(list(G2.nodes())) == len(list(gen_graph.nodes()))
    t = bench_timer(_run)
    assert t >= 0.0
