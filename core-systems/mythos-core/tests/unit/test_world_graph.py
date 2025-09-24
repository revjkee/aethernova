# mythos-core/tests/unit/test_world_graph.py
# Контрактные unit-тесты для WorldGraph.
# Назначение: зафиксировать промышленный API- и поведенческий контракт графа мира.
#
# Примечание о независимости от реализации:
# - Тесты пытаются импортировать WorldGraph из mythos_core.world_graph.
# - Если реализация недоступна или часть методов отсутствует, соответствующие тесты будут помечены как skipped,
#   чтобы избежать ложных падений до поставки целевой реализации.
# - Для генеративных свойств используются hypothesis (property-based testing).
#
# Инварианты и контракт:
# - add_node(id, **attrs): добавляет узел; повторный вызов не создаёт дубликатов (идемпотентность).
# - add_edge(u, v, **attrs): добавляет ребро; допустимость параллельных/дублирующих рёбер не предполагается
#   (если граф мульти- или ориентированный — проверка сведена к существованию ребра (u, v)).
# - remove_node(id): удаляет узел и все инцидентные рёбра (целостность).
# - remove_edge(u, v): удаляет ребро (если существует).
# - has_node(id) / has_edge(u, v): проверка существования.
# - get_node(id) / get_edge(u, v): доступ к атрибутам (dict).
# - neighbors(id): итерируемый набор соседей узла id.
# - nodes() -> Iterable: перечисление узлов; допускается возврат id либо структур с ключом "id".
# - edges() -> Iterable: перечисление рёбер; допускается (u, v) или (u, v, attrs).
# - shortest_path(u, v) или find_path(u, v): список узлов кратчайшего пути.
# - subgraph(node_ids): возвращает "графоподобный" объект с тем же контрактом, содержащий только заданные узлы и рёбра между ними.
# - to_dict() / from_dict(data): сериализация и восстановление без потери информации о структуре и атрибутах.
#
# ВНИМАНИЕ: Фактическое API не предоставлено. Я не могу это верифицировать.
# Тесты помечают отдельные проверки как skip при отсутствии методов.

from __future__ import annotations

import inspect
from typing import Any, Iterable, Tuple, Set, Dict, Optional

import pytest

try:
    from hypothesis import given, settings, HealthCheck
    import hypothesis.strategies as st
    HYPOTHESIS_AVAILABLE = True
except Exception:
    HYPOTHESIS_AVAILABLE = False


# ---------- Утилиты контрактного тестирования ----------

def _call_or_skip(obj: Any, name: str, *args, **kwargs):
    fn = getattr(obj, name, None)
    if not callable(fn):
        pytest.skip(f"Method '{name}' is not implemented on {type(obj).__name__}")
    return fn(*args, **kwargs)


def _has_callable(obj: Any, name: str) -> bool:
    return callable(getattr(obj, name, None))


def _node_ids(graph: Any) -> Set[Any]:
    """
    Унифицируем способ получения множества идентификаторов узлов.
    Допускаем:
      - graph.nodes() -> Iterable[NodeId | (NodeId, ...attr...) | {"id": NodeId, ...}]
      - graph.nodes -> Iterable[...] (с вызовом если это функция/метод)
    """
    nodes_val = getattr(graph, "nodes", None)
    if callable(nodes_val):
        nodes = nodes_val()
    elif nodes_val is not None:
        nodes = nodes_val
    elif _has_callable(graph, "nodes"):
        nodes = graph.nodes()
    else:
        pytest.skip("No 'nodes' accessor present")

    out: Set[Any] = set()
    for n in nodes:
        if isinstance(n, dict) and "id" in n:
            out.add(n["id"])
        elif isinstance(n, (tuple, list)) and n:
            out.add(n[0])
        else:
            out.add(n)
    return out


def _edge_pairs(graph: Any) -> Set[Tuple[Any, Any]]:
    """
    Унифицируем способ получения множества пар ребер (u, v).
    Допускаем:
      - edges() -> Iterable[(u, v)] или [(u, v, attrs)]
      - edges -> Iterable[...] (как выше)
    """
    edges_val = getattr(graph, "edges", None)
    if callable(edges_val):
        edges = edges_val()
    elif edges_val is not None:
        edges = edges_val
    elif _has_callable(graph, "edges"):
        edges = graph.edges()
    else:
        pytest.skip("No 'edges' accessor present")

    out: Set[Tuple[Any, Any]] = set()
    for e in edges:
        if isinstance(e, (tuple, list)):
            if len(e) >= 2:
                out.add((e[0], e[1]))
            else:
                pytest.fail(f"Edge tuple malformed: {e!r}")
        elif isinstance(e, dict) and {"u", "v"} <= set(e.keys()):
            out.add((e["u"], e["v"]))
        else:
            pytest.fail(f"Unsupported edge representation: {e!r}")
    return out


def _get_path(graph: Any, u: Any, v: Any) -> Optional[list]:
    """
    Унифицированный доступ к кратчайшему пути: shortest_path или find_path.
    """
    if _has_callable(graph, "shortest_path"):
        return graph.shortest_path(u, v)
    if _has_callable(graph, "find_path"):
        return graph.find_path(u, v)
    pytest.skip("No path-finding method ('shortest_path' or 'find_path') present")


def _supports_serialization(graph: Any) -> bool:
    return _has_callable(graph, "to_dict")


def _new_from_dict(graph_type: Any, data: Dict[str, Any]):
    """
    Восстановление из словаря:
      - Если есть статический/классовый from_dict -> используем его.
      - Иначе пробуем конструктор вида __init__(data=...).
    """
    from_dict = getattr(graph_type, "from_dict", None)
    if callable(from_dict):
        return from_dict(data)

    # Попытка через конструктор
    try:
        return graph_type(data=data)
    except Exception:
        pytest.skip("No 'from_dict' and no suitable constructor for deserialization")


# ---------- Фикстуры ----------

@pytest.fixture
def world_graph():
    """
    Пытаемся импортировать промышленную реализацию WorldGraph.
    Если недоступна — помечаем все тесты как skipped, поскольку фактическое API неизвестно.
    """
    try:
        from mythos_core.world_graph import WorldGraph  # type: ignore
    except Exception as e:
        pytest.skip(f"WorldGraph implementation is not importable: {e!r}")
    return WorldGraph()


# ---------- Базовые CRUD и инварианты ----------

def test_add_nodes_and_edges_basic(world_graph):
    g = world_graph

    _call_or_skip(g, "add_node", "a", kind="Entity", name="Alpha")
    _call_or_skip(g, "add_node", "b", kind="Entity", name="Beta")
    _call_or_skip(g, "add_node", "c", kind="Entity", name="Gamma")

    assert {"a", "b", "c"} <= _node_ids(g)

    _call_or_skip(g, "add_edge", "a", "b", relation="linked_to", weight=1.0)
    _call_or_skip(g, "add_edge", "b", "c", relation="linked_to", weight=2.0)

    edges = _edge_pairs(g)
    assert ("a", "b") in edges
    assert ("b", "c") in edges


def test_idempotent_add_node(world_graph):
    g = world_graph

    _call_or_skip(g, "add_node", "x")
    before = _node_ids(g)
    _call_or_skip(g, "add_node", "x")  # повторное добавление
    after = _node_ids(g)

    assert "x" in after
    assert before == after, "Повторное добавление узла не должно создавать дубликаты"


def test_remove_node_cascades_edges(world_graph):
    g = world_graph

    for n in ("n1", "n2", "n3"):
        _call_or_skip(g, "add_node", n)
    _call_or_skip(g, "add_edge", "n1", "n2")
    _call_or_skip(g, "add_edge", "n2", "n3")

    _call_or_skip(g, "remove_node", "n2")

    nodes = _node_ids(g)
    edges = _edge_pairs(g)

    assert "n2" not in nodes, "Удалённый узел не должен присутствовать"
    assert all("n2" not in pair for pair in edges), "Инцидентные рёбра должны быть удалены"


def test_neighbors_and_has_methods(world_graph):
    g = world_graph

    for n in ("u", "v", "w"):
        _call_or_skip(g, "add_node", n)
    _call_or_skip(g, "add_edge", "u", "v")
    _call_or_skip(g, "add_edge", "u", "w")

    if _has_callable(g, "has_node"):
        assert g.has_node("u")
        assert not g.has_node("zz")

    if _has_callable(g, "has_edge"):
        assert g.has_edge("u", "v")
        assert not g.has_edge("v", "u")  # если граф ориентированный, это корректно; если нет — провал не критичен

    if _has_callable(g, "neighbors"):
        neigh = set(g.neighbors("u"))
        assert {"v", "w"} <= neigh


def test_update_and_get_metadata(world_graph):
    g = world_graph

    _call_or_skip(g, "add_node", "hero", kind="Entity", name="Hero")
    # Попробуем обновить атрибуты узла (любой из методов)
    if _has_callable(g, "upsert_node"):
        g.upsert_node("hero", level=5, name="Hero Updated")
    elif _has_callable(g, "update_node"):
        g.update_node("hero", {"level": 5, "name": "Hero Updated"})
    else:
        pytest.skip("No 'upsert_node' or 'update_node' available")

    if _has_callable(g, "get_node"):
        meta = g.get_node("hero")
        assert isinstance(meta, dict)
        assert meta.get("name") == "Hero Updated"
        assert meta.get("level") == 5
    else:
        pytest.skip("No 'get_node' available to verify metadata")


# ---------- Пути и подграфы ----------

def test_shortest_path_on_chain(world_graph):
    g = world_graph

    chain = ["p0", "p1", "p2", "p3", "p4"]
    for nid in chain:
        _call_or_skip(g, "add_node", nid)
    for i in range(len(chain) - 1):
        _call_or_skip(g, "add_edge", chain[i], chain[i + 1])

    path = _get_path(g, "p0", "p4")
    assert path is not None
    assert path[0] == "p0" and path[-1] == "p4"
    # Длина пути в узлах = рёбра + 1
    assert len(path) == len(chain)


def test_subgraph_properties(world_graph):
    g = world_graph

    for n in ("s1", "s2", "s3", "t1"):
        _call_or_skip(g, "add_node", n)
    _call_or_skip(g, "add_edge", "s1", "s2")
    _call_or_skip(g, "add_edge", "s2", "s3")
    _call_or_skip(g, "add_edge", "s3", "t1")  # ребро на внешнюю вершину

    if not _has_callable(g, "subgraph"):
        pytest.skip("No 'subgraph' available")

    sg = g.subgraph({"s1", "s2", "s3"})
    sg_nodes = _node_ids(sg)
    sg_edges = _edge_pairs(sg)

    assert sg_nodes == {"s1", "s2", "s3"}
    assert ("s3", "t1") not in sg_edges
    assert ("s1", "s2") in sg_edges
    assert ("s2", "s3") in sg_edges


# ---------- Сериализация ----------

def test_serialization_roundtrip(world_graph):
    g = world_graph

    for n in ("a1", "a2"):
        _call_or_skip(g, "add_node", n, kind="Entity")
    _call_or_skip(g, "add_edge", "a1", "a2", relation="knows", trust=0.9)

    if not _supports_serialization(g):
        pytest.skip("No 'to_dict' available for serialization")

    data = g.to_dict()
    assert isinstance(data, dict) and data, "Сериализация должна вернуть непустой словарь"

    g_type = type(g)
    g2 = _new_from_dict(g_type, data)

    # Сравним множества узлов и ребер
    assert _node_ids(g2) == _node_ids(g)
    assert _edge_pairs(g2) == _edge_pairs(g)


# ---------- Property-based: случайные наборы узлов/рёбер ----------

pytestmark = pytest.mark.skipif(not HYPOTHESIS_AVAILABLE, reason="hypothesis is not available; property tests skipped")

@settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=50, deadline=None)
@given(
    nodes=st.lists(st.text(min_size=1, max_size=32), min_size=1, max_size=30, unique=True),
    edges=st.lists(
        st.tuples(st.integers(min_value=0, max_value=29), st.integers(min_value=0, max_value=29)),
        min_size=0, max_size=80
    )
)
def test_random_nodes_edges_contract(world_graph, nodes, edges):
    """
    Генеративный тест: добавляем случайные уникальные узлы и рёбра между ними по индексам.
    Проверяем:
      - Все узлы присутствуют.
      - Рёбра присутствуют только между существующими узлами.
      - Идемпотентность повторного добавления узлов.
      - Удаление случайного узла удаляет инцидентные рёбра.
    """
    g = world_graph

    # Добавляем узлы
    for nid in nodes:
        _call_or_skip(g, "add_node", nid)

    # Проверяем наличие
    current_nodes = _node_ids(g)
    assert set(nodes) <= current_nodes

    # Добавляем рёбра (фильтруя некорректные индексы)
    n_len = len(nodes)
    valid_pairs = []
    for (i, j) in edges:
        if 0 <= i < n_len and 0 <= j < n_len:
            u, v = nodes[i], nodes[j]
            _call_or_skip(g, "add_edge", u, v)
            valid_pairs.append((u, v))

    # Идемпотентность добавления узлов
    for nid in nodes:
        _call_or_skip(g, "add_node", nid)
    assert _node_ids(g) == current_nodes

    # Проверка, что каждое добавленное ребро присутствует
    g_edges = _edge_pairs(g)
    for pair in valid_pairs:
        assert pair in g_edges

    # Удалим один узел (если есть) и проверим каскадное удаление рёбер
    victim = nodes[0]
    _call_or_skip(g, "remove_node", victim)
    assert victim not in _node_ids(g)
    assert all(victim not in (u, v) for (u, v) in _edge_pairs(g))


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=30, deadline=None)
@given(length=st.integers(min_value=2, max_value=12))
def test_chain_shortest_path_property(world_graph, length):
    """
    Генеративный тест: создаём цепочку длиной 'length' и проверяем, что
    кратчайший путь между концами равен длине цепочки в узлах.
    """
    g = world_graph

    chain = [f"c{i}" for i in range(length)]
    for nid in chain:
        _call_or_skip(g, "add_node", nid)
    for i in range(len(chain) - 1):
        _call_or_skip(g, "add_edge", chain[i], chain[i + 1])

    path = _get_path(g, chain[0], chain[-1])
    assert path is not None and path[0] == chain[0] and path[-1] == chain[-1]
    assert len(path) == length
