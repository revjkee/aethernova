# -*- coding: utf-8 -*-
"""
mythos-core/mythos/graph/world_graph.py

Промышленное in-memory графовое ядро без внешних зависимостей:
- Узлы/рёбра с версией, временными метками, TTL и soft-delete
- Настраиваемая схема: типы, обязательные поля, типы свойств и индексация
- Потокобезопасность (threading.RLock)
- Индексы: по типам, меткам, свойствам (конфигурируемые)
- Поиск: соседи, BFS, Дейкстра (взвешенный), шаблоны триплетов
- Транзакции с CAS (compare-and-set) и откатом
- Сериализация: JSON-слепки, JSONL-экспорт
- События: on_{node,edge}_{added,updated,deleted}

Лицензия: proprietary (Aethernova / Mythos Core)
"""
from __future__ import annotations

import json
import time
import uuid
import heapq
import threading
from dataclasses import dataclass, field, replace, asdict
from datetime import datetime, timezone, timedelta
from typing import (
    Any, Callable, Dict, Iterable, Iterator, List, Mapping, MutableMapping, Optional,
    Sequence, Set, Tuple, Union, Literal, MutableSequence, overload
)
from collections import defaultdict

# ---------------------------
# Типы и утилиты
# ---------------------------

Primitive = Union[str, int, float, bool, None]
JsonValue = Union[Primitive, List["JsonValue"], Dict[str, "JsonValue"]]
PropertyValue = Union[Primitive, datetime, List[Primitive], Dict[str, Primitive]]

Direction = Literal["out", "in", "both"]

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None

def parse_iso(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    return datetime.fromisoformat(s)

def gen_id() -> str:
    return uuid.uuid4().hex

def _ensure_set(iterable: Optional[Iterable[str]]) -> Set[str]:
    return set(iterable or ())

# ---------------------------
# Исключения
# ---------------------------

class GraphError(Exception): ...
class SchemaError(GraphError): ...
class NotFound(GraphError): ...
class Conflict(GraphError): ...
class ValidationError(GraphError): ...

# ---------------------------
# Схема
# ---------------------------

@dataclass(frozen=True)
class NodeRule:
    required_props: Set[str] = field(default_factory=set)
    property_types: Dict[str, type] = field(default_factory=dict)
    indexed_props: Set[str] = field(default_factory=set)

@dataclass(frozen=True)
class EdgeRule:
    required_props: Set[str] = field(default_factory=set)
    property_types: Dict[str, type] = field(default_factory=dict)
    indexed_props: Set[str] = field(default_factory=set)
    directed: bool = True
    default_weight: float = 1.0

@dataclass(frozen=True)
class GraphSchema:
    """
    Схема задаёт допустимые типы узлов/рёбер и их правила.
    """
    node_types: Dict[str, NodeRule] = field(default_factory=dict)
    edge_types: Dict[str, EdgeRule] = field(default_factory=dict)
    allow_unknown_node_types: bool = False
    allow_unknown_edge_types: bool = False

    def validate_node(self, ntype: str, props: Mapping[str, Any]) -> None:
        rule = self.node_types.get(ntype)
        if not rule and not self.allow_unknown_node_types:
            raise SchemaError(f"Unknown node type: {ntype}")
        if not rule:
            return
        missing = rule.required_props - set(props.keys())
        if missing:
            raise ValidationError(f"Missing node properties for type '{ntype}': {sorted(missing)}")
        for k, tp in rule.property_types.items():
            if k in props and props[k] is not None and not isinstance(props[k], tp):
                raise ValidationError(f"Bad type for node.{k}: expected {tp.__name__}, got {type(props[k]).__name__}")

    def validate_edge(self, etype: str, props: Mapping[str, Any]) -> None:
        rule = self.edge_types.get(etype)
        if not rule and not self.allow_unknown_edge_types:
            raise SchemaError(f"Unknown edge type: {etype}")
        if not rule:
            return
        missing = rule.required_props - set(props.keys())
        if missing:
            raise ValidationError(f"Missing edge properties for type '{etype}': {sorted(missing)}")
        for k, tp in rule.property_types.items():
            if k in props and props[k] is not None and not isinstance(props[k], tp):
                raise ValidationError(f"Bad type for edge.{k}: expected {tp.__name__}, got {type(props[k]).__name__}")

    def is_directed(self, etype: str) -> bool:
        rule = self.edge_types.get(etype)
        return True if not rule else rule.directed

    def default_weight(self, etype: str) -> float:
        rule = self.edge_types.get(etype)
        return 1.0 if not rule else rule.default_weight

    def indexed_node_props(self, ntype: str) -> Set[str]:
        return self.node_types.get(ntype, NodeRule()).indexed_props

    def indexed_edge_props(self, etype: str) -> Set[str]:
        return self.edge_types.get(etype, EdgeRule()).indexed_props

# ---------------------------
# Модели
# ---------------------------

@dataclass(frozen=True)
class Node:
    id: str
    type: str
    labels: Set[str] = field(default_factory=set)
    props: Dict[str, PropertyValue] = field(default_factory=dict)
    version: int = 0
    created_at: datetime = field(default_factory=now_utc)
    updated_at: datetime = field(default_factory=now_utc)
    deleted: bool = False
    ttl_sec: Optional[int] = None  # TTL с момента updated_at

    def expires_at(self) -> Optional[datetime]:
        if self.ttl_sec is None:
            return None
        return self.updated_at + timedelta(seconds=self.ttl_sec)

@dataclass(frozen=True)
class Edge:
    id: str
    type: str
    src: str
    dst: str
    weight: float = 1.0
    directed: bool = True
    props: Dict[str, PropertyValue] = field(default_factory=dict)
    version: int = 0
    created_at: datetime = field(default_factory=now_utc)
    updated_at: datetime = field(default_factory=now_utc)
    deleted: bool = False
    ttl_sec: Optional[int] = None

    def expires_at(self) -> Optional[datetime]:
        if self.ttl_sec is None:
            return None
        return self.updated_at + timedelta(seconds=self.ttl_sec)

# ---------------------------
# События
# ---------------------------

EventHandler = Callable[[str, Dict[str, Any]], None]

# ---------------------------
# Граф
# ---------------------------

class WorldGraph:
    """
    Потокобезопасный in-memory граф.
    """
    def __init__(self, schema: Optional(GraphSchema) = None) -> None:
        self._schema = schema or GraphSchema()
        self._lock = threading.RLock()

        # Хранилище
        self._nodes: Dict[str, Node] = {}
        self._edges: Dict[str, Edge] = {}
        self._out_adj: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
        self._in_adj: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))

        # Индексы
        self._nodes_by_type: Dict[str, Set[str]] = defaultdict(set)
        self._edges_by_type: Dict[str, Set[str]] = defaultdict(set)
        self._nodes_by_label: Dict[str, Set[str]] = defaultdict(set)
        # Индексы по свойствам: (type, prop, value) -> ids
        self._node_prop_idx: Dict[Tuple[str, str, Any], Set[str]] = defaultdict(set)
        self._edge_prop_idx: Dict[Tuple[str, str, Any], Set[str]] = defaultdict(set)

        # Подписчики событий
        self._handlers: Dict[str, List[EventHandler]] = defaultdict(list)

    # -----------------------
    # Подписка на события
    # -----------------------
    def on(self, event: str, handler: EventHandler) -> None:
        """
        event: one of
          - node.added, node.updated, node.deleted
          - edge.added, edge.updated, edge.deleted
        """
        with self._lock:
            self._handlers[event].append(handler)

    def _emit(self, event: str, payload: Dict[str, Any]) -> None:
        for h in list(self._handlers.get(event, ())):
            try:
                h(event, payload)
            except Exception:
                # Никогда не роняем граф из-за обработчика событий
                pass

    # -----------------------
    # Узлы
    # -----------------------
    def upsert_node(
        self,
        ntype: str,
        props: Optional[Mapping[str, PropertyValue]] = None,
        *,
        id: Optional[str] = None,
        labels: Optional[Iterable[str]] = None,
        ttl_sec: Optional[int] = None,
        if_version: Optional[int] = None,
    ) -> Node:
        """
        Добавить/обновить узел. CAS: если if_version указан, версия должна совпасть.
        """
        props = dict(props or {})
        labels_set = _ensure_set(labels)

        with self._lock:
            self._schema.validate_node(ntype, props)

            if id and id in self._nodes:
                current = self._nodes[id]
                if if_version is not None and current.version != if_version:
                    raise Conflict(f"Version mismatch: expected {if_version}, got {current.version}")
                new = replace(
                    current,
                    type=ntype,
                    labels=set(labels_set) or current.labels,
                    props=props or current.props,
                    version=current.version + 1,
                    updated_at=now_utc(),
                    ttl_sec=ttl_sec if ttl_sec is not None else current.ttl_sec,
                    deleted=False,
                )
                self._update_node_indexes(current, new)
                self._nodes[id] = new
                self._emit("node.updated", {"before": _n2json(current), "after": _n2json(new)})
                return new

            nid = id or gen_id()
            created = Node(
                id=nid, type=ntype, labels=set(labels_set), props=props,
                version=0, created_at=now_utc(), updated_at=now_utc(),
                deleted=False, ttl_sec=ttl_sec
            )
            self._nodes[nid] = created
            self._add_node_indexes(created)
            self._emit("node.added", {"node": _n2json(created)})
            return created

    def get_node(self, id: str, *, include_deleted: bool = False) -> Node:
        with self._lock:
            n = self._nodes.get(id)
            if not n or (n.deleted and not include_deleted):
                raise NotFound(f"Node not found: {id}")
            return n

    def delete_node(self, id: str, *, hard: bool = False) -> None:
        with self._lock:
            n = self._nodes.get(id)
            if not n:
                raise NotFound(f"Node not found: {id}")
            if hard:
                # Удаляем вместе с рёбрами
                self._remove_node_indexes(n)
                for eid in list(self._out_edges_ids(id)) + list(self._in_edges_ids(id)):
                    self._delete_edge_internal(eid, hard=True)
                del self._nodes[id]
            else:
                if n.deleted:
                    return
                new = replace(n, deleted=True, version=n.version + 1, updated_at=now_utc())
                self._update_node_indexes(n, new)
                self._nodes[id] = new
            self._emit("node.deleted", {"id": id, "hard": hard})

    # -----------------------
    # Рёбра
    # -----------------------
    def upsert_edge(
        self,
        etype: str,
        src: str,
        dst: str,
        props: Optional[Mapping[str, PropertyValue]] = None,
        *,
        id: Optional[str] = None,
        weight: Optional[float] = None,
        directed: Optional[bool] = None,
        ttl_sec: Optional[int] = None,
        if_version: Optional[int] = None,
    ) -> Edge:
        props = dict(props or {})
        with self._lock:
            # Проверка существования узлов
            if src not in self._nodes or dst not in self._nodes:
                raise ValidationError("Both src and dst nodes must exist")

            self._schema.validate_edge(etype, props)
            direct = self._schema.is_directed(etype) if directed is None else directed
            w = (self._schema.default_weight(etype) if weight is None else float(weight))

            if id and id in self._edges:
                current = self._edges[id]
                if if_version is not None and current.version != if_version:
                    raise Conflict(f"Version mismatch: expected {if_version}, got {current.version}")
                new = replace(
                    current,
                    type=etype,
                    src=src,
                    dst=dst,
                    weight=w,
                    directed=direct,
                    props=props or current.props,
                    version=current.version + 1,
                    updated_at=now_utc(),
                    ttl_sec=ttl_sec if ttl_sec is not None else current.ttl_sec,
                    deleted=False,
                )
                self._update_edge_indexes(current, new)
                self._edges[id] = new
                self._emit("edge.updated", {"before": _e2json(current), "after": _e2json(new)})
                return new

            eid = id or gen_id()
            created = Edge(
                id=eid, type=etype, src=src, dst=dst, weight=w,
                directed=direct, props=props, version=0,
                created_at=now_utc(), updated_at=now_utc(),
                deleted=False, ttl_sec=ttl_sec
            )
            self._edges[eid] = created
            self._add_edge_indexes(created)
            self._emit("edge.added", {"edge": _e2json(created)})
            return created

    def get_edge(self, id: str, *, include_deleted: bool = False) -> Edge:
        with self._lock:
            e = self._edges.get(id)
            if not e or (e.deleted and not include_deleted):
                raise NotFound(f"Edge not found: {id}")
            return e

    def delete_edge(self, id: str, *, hard: bool = False) -> None:
        with self._lock:
            self._delete_edge_internal(id, hard=hard)

    def _delete_edge_internal(self, id: str, *, hard: bool) -> None:
        e = self._edges.get(id)
        if not e:
            raise NotFound(f"Edge not found: {id}")
        if hard:
            self._remove_edge_indexes(e)
            del self._edges[id]
        else:
            if e.deleted:
                return
            new = replace(e, deleted=True, version=e.version + 1, updated_at=now_utc())
            self._update_edge_indexes(e, new)
            self._edges[id] = new
        self._emit("edge.deleted", {"id": id, "hard": hard})

    # -----------------------
    # Запросы
    # -----------------------
    def neighbors(self, node_id: str, *, edge_type: Optional[str] = None, direction: Direction = "out") -> List[str]:
        with self._lock:
            if node_id not in self._nodes:
                raise NotFound(f"Node not found: {node_id}")

            res: Set[str] = set()
            if direction in ("out", "both"):
                for et, eids in self._out_adj[node_id].items():
                    if edge_type and et != edge_type:
                        continue
                    for eid in eids:
                        e = self._edges[eid]
                        if not e.deleted:
                            res.add(e.dst)
            if direction in ("in", "both"):
                for et, eids in self._in_adj[node_id].items():
                    if edge_type and et != edge_type:
                        continue
                    for eid in eids:
                        e = self._edges[eid]
                        if not e.deleted:
                            res.add(e.src)
            return list(res)

    def bfs(
        self,
        start: str,
        *,
        depth: int = 3,
        edge_type: Optional[str] = None,
        direction: Direction = "out",
        node_predicate: Optional[Callable[[Node], bool]] = None,
    ) -> List[str]:
        with self._lock:
            if start not in self._nodes:
                raise NotFound(f"Node not found: {start}")
            seen: Set[str] = {start}
            layer = [start]
            out: List[str] = []
            for _ in range(depth):
                nxt: List[str] = []
                for nid in layer:
                    for nb in self.neighbors(nid, edge_type=edge_type, direction=direction):
                        if nb in seen:
                            continue
                        seen.add(nb)
                        n = self._nodes[nb]
                        if not n.deleted and (not node_predicate or node_predicate(n)):
                            out.append(nb)
                            nxt.append(nb)
                layer = nxt
                if not layer:
                    break
            return out

    def shortest_path(self, start: str, goal: str, *, edge_type: Optional[str] = None) -> Tuple[float, List[str]]:
        """
        Кратчайший путь по весу рёбер (Дейкстра). Возвращает (стоимость, путь узлов).
        """
        with self._lock:
            if start not in self._nodes or goal not in self._nodes:
                raise NotFound("Start/goal not found")

            dist: Dict[str, float] = defaultdict(lambda: float("inf"))
            prev: Dict[str, Optional[str]] = {}
            dist[start] = 0.0

            pq: List[Tuple[float, str]] = [(0.0, start)]
            while pq:
                d, u = heapq.heappop(pq)
                if d != dist[u]:
                    continue
                if u == goal:
                    break
                # Выходящие рёбра
                for et, eids in self._out_adj[u].items():
                    if edge_type and et != edge_type:
                        continue
                    for eid in eids:
                        e = self._edges[eid]
                        if e.deleted:
                            continue
                        v = e.dst
                        nd = d + max(0.0, float(e.weight))
                        if nd < dist[v]:
                            dist[v] = nd
                            prev[v] = u
                            heapq.heappush(pq, (nd, v))
            if dist[goal] == float("inf"):
                raise NotFound("No path")
            # Восстановление пути
            path: List[str] = []
            cur: Optional[str] = goal
            while cur is not None:
                path.append(cur)
                cur = prev.get(cur)
            path.reverse()
            return dist[goal], path

    def match(self, subject: Optional[str] = None, etype: Optional[str] = None, obj: Optional[str] = None) -> List[Edge]:
        """
        Примитивное сопоставление шаблону триплета: (s)-[etype]->(o),
        где любое значение может быть None (wildcard).
        """
        with self._lock:
            out: List[Edge] = []
            # Оптимизация по известным id
            candidate_ids: Iterable[str]
            if etype:
                candidate_ids = list(self._edges_by_type.get(etype, ()))
            else:
                candidate_ids = list(self._edges.keys())
            for eid in candidate_ids:
                e = self._edges[eid]
                if e.deleted:
                    continue
                if subject and e.src != subject:
                    continue
                if obj and e.dst != obj:
                    continue
                out.append(e)
            return out

    def find_nodes(
        self,
        *,
        ntype: Optional[str] = None,
        labels_any: Optional[Iterable[str]] = None,
        prop_equals: Optional[Mapping[str, Any]] = None,
        limit: Optional[int] = None
    ) -> List[Node]:
        with self._lock:
            candidates: Optional[Set[str]] = None
            if ntype:
                candidates = set(self._nodes_by_type.get(ntype, set()))
            if labels_any:
                for lb in labels_any:
                    ids = self._nodes_by_label.get(lb, set())
                    candidates = ids if candidates is None else (candidates & ids)
            if prop_equals:
                for k, v in prop_equals.items():
                    # Если знаем тип — используем точный индекс типа, иначе по всем типам
                    ids: Set[str] = set()
                    if ntype:
                        ids |= self._node_prop_idx.get((ntype, k, v), set())
                    else:
                        # скан по всем типам в индексе
                        for (t, pk, pv), s in self._node_prop_idx.items():
                            if pk == k and pv == v:
                                ids |= s
                    candidates = ids if candidates is None else (candidates & ids)

            # Если кандидаты не известны — скан по всем
            pool = candidates if candidates is not None else set(self._nodes.keys())
            out: List[Node] = []
            for nid in pool:
                n = self._nodes[nid]
                if n.deleted:
                    continue
                if limit is not None and len(out) >= limit:
                    break
                out.append(n)
            return out

    # -----------------------
    # Транзакции
    # -----------------------
    class _Txn:
        def __init__(self, g: "WorldGraph") -> None:
            self.g = g
            self.log: List[Tuple[str, Any]] = []

        def record(self, op: str, payload: Any) -> None:
            self.log.append((op, payload))

        def rollback(self) -> None:
            # Откатываем в обратном порядке
            for op, payload in reversed(self.log):
                if op == "node.add":
                    n: Node = payload
                    # физически убрать
                    if n.id in self.g._nodes:
                        self.g._remove_node_indexes(self.g._nodes[n.id])
                        del self.g._nodes[n.id]
                elif op == "node.update":
                    before: Node = payload
                    self.g._update_node_indexes(self.g._nodes[before.id], before)
                    self.g._nodes[before.id] = before
                elif op == "edge.add":
                    e: Edge = payload
                    if e.id in self.g._edges:
                        self.g._remove_edge_indexes(self.g._edges[e.id])
                        del self.g._edges[e.id]
                elif op == "edge.update":
                    before: Edge = payload
                    self.g._update_edge_indexes(self.g._edges[before.id], before)
                    self.g._edges[before.id] = before
                elif op == "node.delete.soft":
                    before: Node = payload
                    self.g._update_node_indexes(self.g._nodes[before.id], before)
                    self.g._nodes[before.id] = before
                elif op == "edge.delete.soft":
                    before: Edge = payload
                    self.g._update_edge_indexes(self.g._edges[before.id], before)
                    self.g._edges[before.id] = before

    def transaction(self) -> "WorldGraph._TxnCtx":
        return WorldGraph._TxnCtx(self)

    class _TxnCtx:
        def __init__(self, g: "WorldGraph") -> None:
            self.g = g
            self.txn = WorldGraph._Txn(g)

        def __enter__(self) -> "WorldGraph._Txn":
            self.g._lock.acquire()
            return self.txn

        def __exit__(self, exc_type, exc, tb) -> None:
            try:
                if exc_type:
                    self.txn.rollback()
            finally:
                self.g._lock.release()

    # -----------------------
    # TTL и очистка
    # -----------------------
    def prune_expired(self, *, hard: bool = True) -> Tuple[int, int]:
        """
        Удаление просроченных по TTL узлов/рёбер. Возвращает (nodes, edges).
        """
        with self._lock:
            now = now_utc()
            ncount = ecount = 0
            for nid, n in list(self._nodes.items()):
                exp = n.expires_at()
                if exp and exp <= now:
                    if hard:
                        self.delete_node(nid, hard=True)
                    else:
                        self.delete_node(nid, hard=False)
                    ncount += 1
            for eid, e in list(self._edges.items()):
                exp = e.expires_at()
                if exp and exp <= now:
                    if hard:
                        self.delete_edge(eid, hard=True)
                    else:
                        self.delete_edge(eid, hard=False)
                    ecount += 1
            return ncount, ecount

    # -----------------------
    # Сериализация
    # -----------------------
    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "meta": {"created_at": iso(now_utc()), "nodes": len(self._nodes), "edges": len(self._edges)},
                "nodes": [_n2json(n) for n in self._nodes.values()],
                "edges": [_e2json(e) for e in self._edges.values()],
                "schema": _schema2json(self._schema),
            }

    def restore(self, data: Mapping[str, Any], *, merge: bool = False) -> None:
        """
        Восстановление слепка. Если merge=False, текущее состояние очищается.
        """
        with self._lock:
            if not merge:
                self.__init__(schema=self._schema)
            # Узлы сначала
            for j in data.get("nodes", []):
                n = _json2node(j)
                self._nodes[n.id] = n
                self._add_node_indexes(n)
            for j in data.get("edges", []):
                e = _json2edge(j)
                self._edges[e.id] = e
                self._add_edge_indexes(e)

    def export_jsonl(self) -> str:
        """
        Экспорт в JSON Lines: по строке на узел/ребро с типом записи.
        """
        with self._lock:
            lines: List[str] = []
            for n in self._nodes.values():
                lines.append(json.dumps({"kind": "node", "data": _n2json(n)}, ensure_ascii=False))
            for e in self._edges.values():
                lines.append(json.dumps({"kind": "edge", "data": _e2json(e)}, ensure_ascii=False))
            return "\n".join(lines)

    # -----------------------
    # Внутренние индексы
    # -----------------------
    def _add_node_indexes(self, n: Node) -> None:
        self._nodes_by_type[n.type].add(n.id)
        for lb in n.labels:
            self._nodes_by_label[lb].add(n.id)
        for k in self._schema.indexed_node_props(n.type):
            v = n.props.get(k)
            self._node_prop_idx[(n.type, k, v)].add(n.id)

    def _remove_node_indexes(self, n: Node) -> None:
        self._nodes_by_type[n.type].discard(n.id)
        for lb in n.labels:
            self._nodes_by_label[lb].discard(n.id)
        for k in self._schema.indexed_node_props(n.type):
            v = n.props.get(k)
            self._node_prop_idx[(n.type, k, v)].discard(n.id)

        # Удаляем из смежности
        for eid in list(self._out_edges_ids(n.id)):
            self._remove_edge_indexes(self._edges[eid])
            del self._edges[eid]
        for eid in list(self._in_edges_ids(n.id)):
            self._remove_edge_indexes(self._edges[eid])
            del self._edges[eid]
        self._out_adj.pop(n.id, None)
        self._in_adj.pop(n.id, None)

    def _update_node_indexes(self, old: Node, new: Node) -> None:
        if old.type != new.type:
            self._nodes_by_type[old.type].discard(old.id)
            self._nodes_by_type[new.type].add(new.id)
            # переиндексация свойств
            for k in self._schema.indexed_node_props(old.type):
                self._node_prop_idx[(old.type, k, old.props.get(k))].discard(old.id)
            for k in self._schema.indexed_node_props(new.type):
                self._node_prop_idx[(new.type, k, new.props.get(k))].add(new.id)
        else:
            # только свойства
            idx_keys = self._schema.indexed_node_props(new.type)
            for k in idx_keys:
                ov, nv = old.props.get(k), new.props.get(k)
                if ov != nv:
                    self._node_prop_idx[(new.type, k, ov)].discard(old.id)
                    self._node_prop_idx[(new.type, k, nv)].add(new.id)

        # Метки
        if old.labels != new.labels:
            for lb in old.labels - new.labels:
                self._nodes_by_label[lb].discard(old.id)
            for lb in new.labels - old.labels:
                self._nodes_by_label[lb].add(new.id)

    def _add_edge_indexes(self, e: Edge) -> None:
        self._edges_by_type[e.type].add(e.id)
        self._out_adj[e.src][e.type].add(e.id)
        self._in_adj[e.dst][e.type].add(e.id)
        if not e.directed:
            # двунаправленное
            self._out_adj[e.dst][e.type].add(e.id)
            self._in_adj[e.src][e.type].add(e.id)
        for k in self._schema.indexed_edge_props(e.type):
            self._edge_prop_idx[(e.type, k, e.props.get(k))].add(e.id)

    def _remove_edge_indexes(self, e: Edge) -> None:
        self._edges_by_type[e.type].discard(e.id)
        self._out_adj[e.src][e.type].discard(e.id)
        self._in_adj[e.dst][e.type].discard(e.id)
        if not e.directed:
            self._out_adj[e.dst][e.type].discard(e.id)
            self._in_adj[e.src][e.type].discard(e.id)
        for k in self._schema.indexed_edge_props(e.type):
            self._edge_prop_idx[(e.type, k, e.props.get(k))].discard(e.id)

    def _update_edge_indexes(self, old: Edge, new: Edge) -> None:
        if old.type != new.type or old.src != new.src or old.dst != new.dst or old.directed != new.directed:
            self._remove_edge_indexes(old)
            self._add_edge_indexes(new)
        else:
            # только свойства
            idx_keys = self._schema.indexed_edge_props(new.type)
            for k in idx_keys:
                ov, nv = old.props.get(k), new.props.get(k)
                if ov != nv:
                    self._edge_prop_idx[(new.type, k, ov)].discard(old.id)
                    self._edge_prop_idx[(new.type, k, nv)].add(new.id)

    def _out_edges_ids(self, nid: str) -> List[str]:
        return [eid for eids in self._out_adj[nid].values() for eid in eids]

    def _in_edges_ids(self, nid: str) -> List[str]:
        return [eid for eids in self._in_adj[nid].values() for eid in eids]

# ---------------------------
# JSON helpers
# ---------------------------

def _n2json(n: Node) -> Dict[str, Any]:
    return {
        "id": n.id,
        "type": n.type,
        "labels": sorted(n.labels),
        "props": _props_dump(n.props),
        "version": n.version,
        "created_at": iso(n.created_at),
        "updated_at": iso(n.updated_at),
        "deleted": n.deleted,
        "ttl_sec": n.ttl_sec,
    }

def _e2json(e: Edge) -> Dict[str, Any]:
    return {
        "id": e.id,
        "type": e.type,
        "src": e.src,
        "dst": e.dst,
        "weight": e.weight,
        "directed": e.directed,
        "props": _props_dump(e.props),
        "version": e.version,
        "created_at": iso(e.created_at),
        "updated_at": iso(e.updated_at),
        "deleted": e.deleted,
        "ttl_sec": e.ttl_sec,
    }

def _props_dump(p: Mapping[str, PropertyValue]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in p.items():
        if isinstance(v, datetime):
            out[k] = {"$dt": v.isoformat()}
        else:
            out[k] = v
    return out

def _props_load(p: Mapping[str, Any]) -> Dict[str, PropertyValue]:
    out: Dict[str, PropertyValue] = {}
    for k, v in p.items():
        if isinstance(v, dict) and "$dt" in v:
            out[k] = parse_iso(v["$dt"])  # type: ignore[assignment]
        else:
            out[k] = v  # type: ignore[assignment]
    return out

def _json2node(j: Mapping[str, Any]) -> Node:
    return Node(
        id=j["id"],
        type=j["type"],
        labels=set(j.get("labels", [])),
        props=_props_load(j.get("props", {})),
        version=int(j.get("version", 0)),
        created_at=parse_iso(j.get("created_at")) or now_utc(),
        updated_at=parse_iso(j.get("updated_at")) or now_utc(),
        deleted=bool(j.get("deleted", False)),
        ttl_sec=j.get("ttl_sec"),
    )

def _json2edge(j: Mapping[str, Any]) -> Edge:
    return Edge(
        id=j["id"],
        type=j["type"],
        src=j["src"],
        dst=j["dst"],
        weight=float(j.get("weight", 1.0)),
        directed=bool(j.get("directed", True)),
        props=_props_load(j.get("props", {})),
        version=int(j.get("version", 0)),
        created_at=parse_iso(j.get("created_at")) or now_utc(),
        updated_at=parse_iso(j.get("updated_at")) or now_utc(),
        deleted=bool(j.get("deleted", False)),
        ttl_sec=j.get("ttl_sec"),
    )

def _schema2json(s: GraphSchema) -> Dict[str, Any]:
    return {
        "node_types": {
            t: {
                "required_props": sorted(r.required_props),
                "property_types": {k: v.__name__ for k, v in r.property_types.items()},
                "indexed_props": sorted(r.indexed_props),
            } for t, r in s.node_types.items()
        },
        "edge_types": {
            t: {
                "required_props": sorted(r.required_props),
                "property_types": {k: v.__name__ for k, v in r.property_types.items()},
                "indexed_props": sorted(r.indexed_props),
                "directed": r.directed,
                "default_weight": r.default_weight,
            } for t, r in s.edge_types.items()
        },
        "allow_unknown_node_types": s.allow_unknown_node_types,
        "allow_unknown_edge_types": s.allow_unknown_edge_types,
    }

# ---------------------------
# Пример дефолтной схемы (по необходимости импортируйте и переопределяйте)
# ---------------------------

DEFAULT_SCHEMA = GraphSchema(
    node_types={
        "entity": NodeRule(
            required_props=set(),
            property_types={"name": str},
            indexed_props={"name"},
        ),
        "person": NodeRule(
            required_props={"name"},
            property_types={"name": str, "birth_year": int},
            indexed_props={"name", "birth_year"},
        ),
        "place": NodeRule(
            required_props={"name"},
            property_types={"name": str, "country": str},
            indexed_props={"name", "country"},
        ),
    },
    edge_types={
        "related": EdgeRule(
            required_props=set(),
            property_types={"kind": str},
            indexed_props={"kind"},
            directed=False,
            default_weight=1.0,
        ),
        "knows": EdgeRule(
            required_props=set(),
            property_types={"since": int},
            indexed_props={"since"},
            directed=True,
            default_weight=1.0,
        ),
        "located_in": EdgeRule(
            required_props=set(),
            property_types={},
            indexed_props=set(),
            directed=True,
            default_weight=1.0,
        ),
    },
    allow_unknown_node_types=False,
    allow_unknown_edge_types=False,
)

# ---------------------------
# Пример использования (документация)
# ---------------------------
"""
from mythos.graph.world_graph import WorldGraph, DEFAULT_SCHEMA

g = WorldGraph(schema=DEFAULT_SCHEMA)
a = g.upsert_node("person", {"name": "Alice", "birth_year": 1990}, labels={"human"})
b = g.upsert_node("person", {"name": "Bob"}, labels={"human"})
c = g.upsert_node("place", {"name": "Stockholm", "country": "SE"}, labels={"city"})

g.upsert_edge("knows", a.id, b.id, {"since": 2010})
g.upsert_edge("located_in", c.id, b.id)  # пример произвольного ребра

print(g.neighbors(a.id))                # -> [b.id]
print(g.find_nodes(ntype="person", prop_equals={"name": "Alice"}))
print(g.shortest_path(a.id, b.id))
snap = g.snapshot()
g2 = WorldGraph(schema=DEFAULT_SCHEMA)
g2.restore(snap)
"""
