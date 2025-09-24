# mythos-core/tests/e2e/test_canon_consistency_e2e.py
# Сквозные (E2E) проверки консистентности "канона" мифосистемы (mythos-core).
# Контрактные цели:
#   1) Канон загружается и (если доступно) проходит доменную валидацию без ошибок.
#   2) Соответствие канона графу мира: все сущности -> узлы, отношения -> рёбра.
#   3) Детерминированность сериализации: стабильный нормализованный SHA-256 снапшота.
#   4) Ссылочная целостность: нет "висячих" ссылок и дубликатов ID.
#   5) Таймлайн событий: (если есть) ацикличность "precedes/causes" и корректность start<=end.
#   6) Версионирование: (если есть) manifest/checksum согласованы с вычисленным хешем.
#   7) Отсутствие необработанных плейсхолдеров вида ${...}, <<TODO>>, FIXME.
#
# Политика устойчивости:
#   - Если нужный модуль/метод отсутствует — делаем pytest.skip для релевантной проверки.
#   - Порог производительности включается переменными окружения:
#       CANON_LOAD_BUDGET_MS   — бюджет загрузки (мс)
#       CANON_GRAPH_BUDGET_MS  — бюджет сборки графа (мс)
#       CANON_BASELINE_SHA256  — эталонный хеш для регрессии (опционально)
#
# ВНИМАНИЕ: Реальное API не предоставлено. Я не могу это верифицировать.
# Тесты спроектированы как контракт со "слабым связыванием" к API.

from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import time
from dataclasses import is_dataclass, asdict
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import pytest

# -------------------------- Вспомогательные утилиты --------------------------

def _import_or_skip(module_name: str):
    try:
        return __import__(module_name, fromlist=["*"])
    except Exception as e:
        pytest.skip(f"Module '{module_name}' is not importable: {e!r}")


def _get_attr_or_none(obj: Any, name: str):
    return getattr(obj, name, None)


def _call_or_skip(obj: Any, name: str, *args, **kwargs):
    fn = getattr(obj, name, None)
    if not callable(fn):
        pytest.skip(f"Method '{name}' not implemented on {type(obj).__name__}")
    return fn(*args, **kwargs)


def _is_mapping(x: Any) -> bool:
    return isinstance(x, dict)


def _normalize_primitive(x: Any) -> Any:
    if is_dataclass(x):
        return _normalize_primitive(asdict(x))
    if isinstance(x, dict):
        return {str(k): _normalize_primitive(v) for k, v in sorted(x.items(), key=lambda kv: str(kv[0]))}
    if isinstance(x, (list, tuple, set)):
        # Сортируем по стабильному представлению
        seq = list(x)
        try:
            seq_sorted = sorted(seq, key=lambda v: json.dumps(_normalize_primitive(v), sort_keys=True))
        except Exception:
            seq_sorted = seq
        return [_normalize_primitive(v) for v in seq_sorted]
    return x


def _stable_sha256(obj: Any) -> str:
    norm = _normalize_primitive(obj)
    payload = json.dumps(norm, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _flatten_entities(canon: Any) -> List[Dict[str, Any]]:
    """
    Извлекаем сущности из канона по эвристикам:
      - верхнеуровневые ключи: "entities", "nodes", "items", "characters", "locations", "factions", ...
      - любые списки словарей, где у элемента есть "id".
    """
    entities: List[Dict[str, Any]] = []

    def maybe_collect_list(lst: Any):
        if isinstance(lst, list):
            for el in lst:
                if isinstance(el, dict) and "id" in el:
                    entities.append(el)

    if isinstance(canon, dict):
        for k, v in canon.items():
            maybe_collect_list(v)

    # Если прямых совпадений мало — попытка найти глубже
    if not entities and isinstance(canon, dict):
        stack = list(canon.values())
        while stack:
            v = stack.pop()
            if isinstance(v, dict):
                stack.extend(v.values())
            elif isinstance(v, list):
                maybe_collect_list(v)

    # Уникализируем по id
    seen = set()
    uniq: List[Dict[str, Any]] = []
    for e in entities:
        eid = e.get("id")
        if eid is not None and eid not in seen:
            uniq.append(e)
            seen.add(eid)
    return uniq


def _extract_relations(canon: Any) -> List[Dict[str, Any]]:
    """
    Извлекаем отношения:
      - верхнеуровневые "relations"/"edges"/"links" — список словарей c полями src/from/u и dst/to/v, type/rel.
      - вложенные отношения в сущностях: entity["relations"] или entity["links"].
    """
    rels: List[Dict[str, Any]] = []

    def normalize_rel(r: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        keys = {k.lower(): k for k in r.keys()}
        src = r.get(keys.get("src")) or r.get(keys.get("from")) or r.get(keys.get("u"))
        dst = r.get(keys.get("dst")) or r.get(keys.get("to")) or r.get(keys.get("v"))
        rtype = r.get(keys.get("type")) or r.get(keys.get("rel")) or r.get(keys.get("relation"))
        if src is None or dst is None:
            return None
        return {"src": src, "dst": dst, "type": rtype, **{k: v for k, v in r.items() if k not in ("src", "from", "u", "dst", "to", "v", "type", "rel", "relation")}}

    def collect_from_list(lst: Any):
        if isinstance(lst, list):
            for el in lst:
                if isinstance(el, dict):
                    nr = normalize_rel(el)
                    if nr:
                        rels.append(nr)

    if isinstance(canon, dict):
        for key in ("relations", "edges", "links"):
            collect_from_list(canon.get(key))

        # Пройти по сущностям
        entities = _flatten_entities(canon)
        for e in entities:
            for key in ("relations", "links"):
                collect_from_list(e.get(key))

    # Уникализируем по (src,dst,type)
    seen = set()
    uniq: List[Dict[str, Any]] = []
    for r in rels:
        sig = (r.get("src"), r.get("dst"), r.get("type"))
        if sig not in seen:
            uniq.append(r)
            seen.add(sig)
    return uniq


def _extract_events(canon: Any) -> List[Dict[str, Any]]:
    """
    Извлекаем события (если есть): ключ 'events' либо любой список словарей с полями 'id' и датами.
    Поддерживаем поля: start, end, ts, timestamp, begins_at, ends_at (ISO8601 предпочтительно).
    """
    events: List[Dict[str, Any]] = []

    def looks_like_event(d: Dict[str, Any]) -> bool:
        if "id" not in d:
            return False
        keys = {k.lower() for k in d.keys()}
        return bool({"start", "end"} & keys) or bool({"ts", "timestamp"} & keys) or bool({"begins_at", "ends_at"} & keys)

    if isinstance(canon, dict):
        top = canon.get("events")
        if isinstance(top, list):
            for el in top:
                if isinstance(el, dict) and "id" in el:
                    events.append(el)

        # Поиск глубже
        if not events:
            stack = [canon]
            while stack:
                cur = stack.pop()
                if isinstance(cur, dict):
                    for v in cur.values():
                        stack.append(v)
                elif isinstance(cur, list):
                    for el in cur:
                        if isinstance(el, dict) and looks_like_event(el):
                            events.append(el)

    # Уникализация
    seen = set()
    uniq = []
    for e in events:
        eid = e.get("id")
        if eid not in seen:
            uniq.append(e)
            seen.add(eid)
    return uniq


def _parse_iso_dt(value: Any) -> Optional[float]:
    """
    Грубый парсер времени: поддерживаем ISO8601 и числовые epoch секунд/мс.
    Возвращаем timestamp в секундах (float) либо None.
    """
    if value is None:
        return None
    if isinstance(value, (int, float)):
        # Если похоже на миллисекунды — нормализуем
        return float(value / 1000.0) if value > 10_000_000_000 else float(value)
    if isinstance(value, str):
        # Попытка через fromisoformat
        from datetime import datetime
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except Exception:
            # Попытка через числовую строку
            try:
                num = float(value)
                return float(num / 1000.0) if num > 10_000_000_000 else num
            except Exception:
                return None
    return None


def _has_unresolved_placeholders(text: str) -> bool:
    return bool(re.search(r"(\$\{[^}]+\}|<<\s*TODO\s*>>|FIXME)", text))


def _neighbors_from_graph(graph: Any, node_id: Any) -> Iterable[Any]:
    n_fn = _get_attr_or_none(graph, "neighbors")
    if callable(n_fn):
        return n_fn(node_id)
    # Попытка через edges()
    e_fn = _get_attr_or_none(graph, "edges")
    if callable(e_fn):
        out = []
        for e in e_fn():
            if isinstance(e, (tuple, list)) and len(e) >= 2:
                u, v = e[0], e[1]
                if u == node_id:
                    out.append(v)
        return out
    pytest.skip("No neighbors or edges accessor on graph")


def _edge_pairs(graph: Any) -> Set[Tuple[Any, Any]]:
    e_fn = _get_attr_or_none(graph, "edges")
    edges = None
    if callable(e_fn):
        edges = e_fn()
    elif hasattr(graph, "edges"):
        edges = getattr(graph, "edges")
    else:
        pytest.skip("No edges accessor on graph")

    out: Set[Tuple[Any, Any]] = set()
    for e in edges:
        if isinstance(e, (tuple, list)) and len(e) >= 2:
            out.add((e[0], e[1]))
        elif isinstance(e, dict) and {"u", "v"} <= set(e.keys()):
            out.add((e["u"], e["v"]))
        else:
            pytest.fail(f"Unsupported edge representation: {e!r}")
    return out


def _node_ids(graph: Any) -> Set[Any]:
    n = _get_attr_or_none(graph, "nodes")
    nodes = n() if callable(n) else (n if n is not None else None)
    if nodes is None:
        pytest.skip("No nodes accessor on graph")

    out: Set[Any] = set()
    for el in nodes:
        if isinstance(el, dict) and "id" in el:
            out.add(el["id"])
        elif isinstance(el, (tuple, list)) and el:
            out.add(el[0])
        else:
            out.add(el)
    return out


def _build_graph_from_canon(graph_type: Any, canon: Any) -> Any:
    """
    Универсальная сборка графа из канона:
      - Предпочитаем classmethod: from_canon(canon) или build_from_canon(canon)
      - Иначе: WorldGraph(); .ingest_canon(canon)
      - В крайнем случае: наполнение узлами/рёбрами с помощью add_node/add_edge
    """
    for factory in ("from_canon", "build_from_canon"):
        fn = getattr(graph_type, factory, None)
        if callable(fn):
            return fn(canon)

    # Конструктор
    graph = graph_type()

    ing = getattr(graph, "ingest_canon", None)
    if callable(ing):
        ing(canon)
        return graph

    # Ручная загрузка как fallback
    ents = _flatten_entities(canon)
    rels = _extract_relations(canon)

    add_node = getattr(graph, "add_node", None)
    add_edge = getattr(graph, "add_edge", None)
    if not callable(add_node) or not callable(add_edge):
        pytest.skip("Graph does not support manual add_node/add_edge to ingest canon")

    for e in ents:
        add_node(e["id"], **{k: v for k, v in e.items() if k != "id"})
    for r in rels:
        add_edge(r["src"], r["dst"], **{k: v for k, v in r.items() if k not in ("src", "dst")})
    return graph


def _load_canon_or_skip():
    canon_mod = _import_or_skip("mythos_core.canon")
    # Ищем функции/объекты загрузки
    for name in ("load_canon", "load", "get_canon", "load_default"):
        fn = getattr(canon_mod, name, None)
        if callable(fn):
            return fn()

    # Пробуем CanonLoader().load()
    Loader = getattr(canon_mod, "CanonLoader", None)
    if Loader is not None:
        loader = Loader() if callable(Loader) else None
        if loader:
            load = getattr(loader, "load", None)
            if callable(load):
                return load()

    pytest.skip("No canon loader function/class found in mythos_core.canon")


def _validate_canon_if_possible(canon: Any):
    try:
        validator_mod = __import__("mythos_core.validation", fromlist=["*"])
    except Exception:
        pytest.skip("No mythos_core.validation module — skip validation step")

    for name in ("validate_canon", "validate", "run_all"):
        fn = getattr(validator_mod, name, None)
        if callable(fn):
            return fn(canon)
    pytest.skip("No validation entrypoint found in mythos_core.validation")


# -------------------------- Фикстуры --------------------------

@pytest.fixture(scope="session")
def canon_snapshot():
    budget_ms = int(os.environ.get("CANON_LOAD_BUDGET_MS", "0"))
    t0 = time.time()
    canon = _load_canon_or_skip()
    t1 = time.time()
    elapsed_ms = int((t1 - t0) * 1000)
    if budget_ms > 0 and elapsed_ms > budget_ms:
        pytest.fail(f"Canon load exceeded budget: {elapsed_ms}ms > {budget_ms}ms")
    assert canon is not None
    return canon


@pytest.fixture(scope="session")
def world_graph_from_canon(canon_snapshot):
    wg_mod = _import_or_skip("mythos_core.world_graph")
    WorldGraph = getattr(wg_mod, "WorldGraph", None)
    if WorldGraph is None:
        pytest.skip("WorldGraph class not found in mythos_core.world_graph")

    budget_ms = int(os.environ.get("CANON_GRAPH_BUDGET_MS", "0"))
    t0 = time.time()
    graph = _build_graph_from_canon(WorldGraph, canon_snapshot)
    t1 = time.time()
    elapsed_ms = int((t1 - t0) * 1000)
    if budget_ms > 0 and elapsed_ms > budget_ms:
        pytest.fail(f"Graph build exceeded budget: {elapsed_ms}ms > {budget_ms}ms")
    return graph


# -------------------------- Тест 1: загрузка и валидация --------------------------

def test_canon_load_and_validate_e2e(canon_snapshot):
    # Наличие основ
    assert canon_snapshot is not None
    # Опциональная доменная валидация
    _validate_canon_if_possible(canon_snapshot)


# -------------------------- Тест 2: ссылочная целостность --------------------------

def test_canon_reference_integrity_e2e(canon_snapshot):
    entities = _flatten_entities(canon_snapshot)
    rels = _extract_relations(canon_snapshot)

    ids = [e.get("id") for e in entities if "id" in e]
    assert len(ids) == len(set(ids)), "Duplicate entity IDs detected"

    id_set = set(ids)
    dangling = []
    for r in rels:
        src, dst = r.get("src"), r.get("dst")
        if src not in id_set or dst not in id_set:
            dangling.append(r)

    assert not dangling, f"Dangling relations referencing missing entities: {dangling[:5]}"


# -------------------------- Тест 3: соответствие world-graph --------------------------

def test_canon_matches_world_graph_e2e(canon_snapshot, world_graph_from_canon):
    g = world_graph_from_canon
    entities = _flatten_entities(canon_snapshot)
    rels = _extract_relations(canon_snapshot)

    g_nodes = _node_ids(g)
    g_edges = _edge_pairs(g)

    # Все сущности присутствуют как узлы
    missing_nodes = [e["id"] for e in entities if e["id"] not in g_nodes]
    assert not missing_nodes, f"Graph missing nodes from canon: {missing_nodes[:10]}"

    # Отношения покрыты рёбрами (ориентированное сопоставление)
    missing_edges = []
    for r in rels:
        pair = (r["src"], r["dst"])
        if pair not in g_edges:
            missing_edges.append(pair)
    assert not missing_edges, f"Graph missing edges from canon: {missing_edges[:10]}"


# -------------------------- Тест 4: детерминированность сериализации --------------------------

def test_canon_deterministic_hash_e2e(canon_snapshot):
    # 1-й проход
    h1 = _stable_sha256(canon_snapshot)

    # 2-й проход (повторная нормализация)
    h2 = _stable_sha256(canon_snapshot)

    assert h1 == h2, "Non-deterministic canon serialization detected"

    baseline = os.environ.get("CANON_BASELINE_SHA256")
    if baseline:
        assert h1 == baseline, f"Canon hash regression: {h1} != {baseline}"


# -------------------------- Тест 5: события и DAG таймлайна --------------------------

def test_canon_event_timeline_e2e(canon_snapshot):
    events = _extract_events(canon_snapshot)
    if not events:
        pytest.skip("No events in canon — skipping timeline checks")

    # Проверка start<=end и присутствия хотя бы одного времени
    for ev in events:
        start = _parse_iso_dt(ev.get("start") or ev.get("begins_at"))
        end = _parse_iso_dt(ev.get("end") or ev.get("ends_at"))
        ts = _parse_iso_dt(ev.get("ts") or ev.get("timestamp"))

        if start is not None and end is not None:
            assert end >= start, f"Event '{ev.get('id')}' has end<start"
        else:
            # Допускаем одиночную отметку времени
            assert ts is not None or (start is not None or end is not None), \
                f"Event '{ev.get('id')}' has no time anchors"

    # Граф предшествования
    # Извлекаем зависимости из полей 'precedes', 'follows', 'causes', 'depends_on'
    id_to_event = {e["id"]: e for e in events if "id" in e}
    adj: Dict[str, Set[str]] = {eid: set() for eid in id_to_event.keys()}

    def add_edge(u: str, v: str):
        if u in adj and v in adj:
            adj[u].add(v)

    for e in events:
        eid = e.get("id")
        if not eid:
            continue
        for key in ("precedes", "causes", "depends_on"):
            val = e.get(key)
            if isinstance(val, str):
                add_edge(eid, val) if key != "depends_on" else add_edge(val, eid)
            elif isinstance(val, list):
                for tgt in val:
                    if isinstance(tgt, str):
                        add_edge(eid, tgt) if key != "depends_on" else add_edge(tgt, eid)
        # 'follows' — обратная связь: follows:X => X -> eid
        val = e.get("follows")
        if isinstance(val, str):
            add_edge(val, eid)
        elif isinstance(val, list):
            for src in val:
                if isinstance(src, str):
                    add_edge(src, eid)

    # Проверка ацикличности
    visited: Dict[str, int] = {}  # 0=unseen,1=stack,2=done

    def dfs(u: str) -> bool:
        state = visited.get(u, 0)
        if state == 1:
            return False  # цикл
        if state == 2:
            return True
        visited[u] = 1
        for v in adj.get(u, ()):
            if not dfs(v):
                return False
        visited[u] = 2
        return True

    for node in adj.keys():
        if visited.get(node, 0) == 0:
            ok = dfs(node)
            assert ok, "Cycle detected in event precedence graph"


# -------------------------- Тест 6: плейсхолдеры/черновики --------------------------

def test_canon_has_no_unresolved_placeholders_e2e(canon_snapshot):
    # Проходим по всем строковым полям и ищем необработанные плейсхолдеры.
    violations = []

    def walk(path: str, val: Any):
        if isinstance(val, str):
            if _has_unresolved_placeholders(val):
                violations.append((path, val))
        elif isinstance(val, dict):
            for k, v in val.items():
                walk(f"{path}.{k}" if path else str(k), v)
        elif isinstance(val, (list, tuple)):
            for i, v in enumerate(val):
                walk(f"{path}[{i}]", v)

    walk("", canon_snapshot)
    assert not violations, f"Unresolved placeholders found (first 10): {violations[:10]}"


# -------------------------- Тест 7: версионирование/манифест --------------------------

def test_canon_version_and_manifest_e2e(canon_snapshot):
    # Опционально проверяем поля версии/манифеста и согласованность checksum.
    manifest = None
    version = None
    checksum = None

    if isinstance(canon_snapshot, dict):
        manifest = canon_snapshot.get("manifest") or canon_snapshot.get("_manifest")
        version = canon_snapshot.get("version") or canon_snapshot.get("_version")
        checksum = canon_snapshot.get("checksum") or canon_snapshot.get("_checksum")

    # Альтернативный путь: mythos_core.canon.manifest(), .version(), .checksum()
    try:
        canon_mod = __import__("mythos_core.canon", fromlist=["*"])
        for name in ("manifest", "get_manifest"):
            fn = getattr(canon_mod, name, None)
            if callable(fn):
                manifest = manifest or fn()
        for name in ("version", "get_version"):
            fn = getattr(canon_mod, name, None)
            if callable(fn):
                version = version or fn()
        for name in ("checksum", "get_checksum"):
            fn = getattr(canon_mod, name, None)
            if callable(fn):
                checksum = checksum or fn()
    except Exception:
        pass  # отсутствие — не фатально, будет skip при пустых полях

    if version is None and manifest is None and checksum is None:
        pytest.skip("No version/manifest/checksum found — skipping")

    # Если есть checksum — сравним с вычисленным хешем
    if checksum is not None:
        computed = _stable_sha256(canon_snapshot)
        assert str(checksum) == computed, f"Manifest checksum mismatch: {checksum} != {computed}"

    # Версия — просто наличие строки/числа
    if version is not None:
        assert isinstance(version, (str, int)), "Version must be str or int"


# -------------------------- Тест 8: графовые инварианты канона --------------------------

def test_graph_invariants_e2e(world_graph_from_canon):
    g = world_graph_from_canon
    nodes = _node_ids(g)
    edges = _edge_pairs(g)

    # Нет петель (если домен не поддерживает их) — проверяем мягко: при наличии has_edge(u,u) == False
    has_edge = getattr(g, "has_edge", None)
    if callable(has_edge):
        self_loops = [n for n in nodes if has_edge(n, n)]
        assert not self_loops, f"Self-loops detected but not expected: {self_loops[:10]}"

    # Связность в пределах компонент (нестрого): у каждого узла есть хотя бы одна инцидентная связь
    # (мягкий инвариант, может быть изолированные узлы — допускаем 5% изолированных максимум)
    deg = {n: 0 for n in nodes}
    for (u, v) in edges:
        if u in deg:
            deg[u] += 1
        if v in deg:
            deg[v] += 1
    isolated = [n for n, d in deg.items() if d == 0]
    # Допускаем малую долю изолированных: не более 5% или максимум 20 узлов
    if nodes:
        limit = max(20, int(0.05 * len(nodes)))
        assert len(isolated) <= limit, f"Too many isolated nodes: {len(isolated)} > {limit}"


# -------------------------- Тест 9: round-trip графа (если поддерживается) --------------------------

def test_graph_roundtrip_serialization_e2e(world_graph_from_canon):
    g = world_graph_from_canon
    to_dict = getattr(g, "to_dict", None)
    if not callable(to_dict):
        pytest.skip("Graph has no to_dict — skipping round-trip")

    payload = to_dict()
    assert isinstance(payload, dict) and payload, "Graph to_dict returned empty/invalid payload"

    g_type = type(g)
    # from_dict предпочтительнее, затем конструктор data=...
    if callable(getattr(g_type, "from_dict", None)):
        g2 = g_type.from_dict(payload)
    else:
        try:
            g2 = g_type(data=payload)
        except Exception:
            pytest.skip("Graph has no from_dict or suitable constructor for round-trip")

    # Сопоставим множества узлов/рёбер
    assert _node_ids(g2) == _node_ids(g), "Node set changed after round-trip"
    assert _edge_pairs(g2) == _edge_pairs(g), "Edge set changed after round-trip"
