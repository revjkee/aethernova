# engine-core/engine/mocks/graph_mock.py
# Industrial-grade in-memory property graph mock for tests and local dev.
# Features:
# - Property graph: nodes/edges with labels and arbitrary attributes
# - Deterministic data generation (seedable)
# - Transactions with rollback (context manager)
# - Event hooks (on_add/remove/update) for assertions
# - Metrics counters
# - Concurrency safety (thread + asyncio compatible)
# - Queries: degree, neighbors, BFS, Dijkstra (weight), subgraphs, predicates
# - Serialization: JSON (stable), from_json
# - Sync & Async API

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Set, Tuple, Union
from contextlib import contextmanager
from collections import defaultdict, deque
import math
import random
import asyncio

# ----------------------------
# Errors
# ----------------------------
class GraphError(Exception):
    pass

class NodeExistsError(GraphError):
    pass

class NodeNotFoundError(GraphError):
    pass

class EdgeNotFoundError(GraphError):
    pass


# ----------------------------
# Models
# ----------------------------
@dataclass(frozen=True)
class Node:
    id: str
    label: str = "node"
    props: Dict[str, Any] = field(default_factory=dict)

    def with_props(self, **updates: Any) -> "Node":
        p = dict(self.props)
        p.update(updates)
        return Node(id=self.id, label=self.label, props=p)

@dataclass(frozen=True)
class Edge:
    id: str
    src: str
    dst: str
    label: str = "edge"
    weight: float = 1.0
    props: Dict[str, Any] = field(default_factory=dict)


# ----------------------------
# Metrics
# ----------------------------
@dataclass
class GraphMetrics:
    nodes_added: int = 0
    nodes_removed: int = 0
    edges_added: int = 0
    edges_removed: int = 0
    tx_committed: int = 0
    tx_rolled_back: int = 0
    queries_total: int = 0
    last_query_ms: Optional[float] = None

    def snapshot(self) -> Dict[str, Any]:
        return asdict(self)


# ----------------------------
# Transaction
# ----------------------------
@dataclass
class GraphTransaction:
    # Stores inverse ops for rollback
    undo_stack: List[Tuple[str, Any]] = field(default_factory=list)
    active: bool = True

    def record(self, op: str, payload: Any) -> None:
        if self.active:
            self.undo_stack.append((op, payload))

    def rollback(self, g: "GraphMock") -> None:
        # Apply in reverse
        while self.undo_stack:
            op, payload = self.undo_stack.pop()
            if op == "del_node":
                node: Node = payload
                g._unsafe_add_node(node)
            elif op == "del_edge":
                edge: Edge = payload
                g._unsafe_add_edge(edge)
            elif op == "set_node":
                # payload: (old_node)
                old_node: Node = payload
                g._unsafe_set_node(old_node)
            elif op == "set_weight":
                # payload: (edge_id, old_weight)
                eid, old_w = payload
                g._unsafe_set_edge_weight(eid, old_w)
        self.active = False


# ----------------------------
# Core Graph
# ----------------------------
class GraphMock:
    def __init__(self, *, seed: Optional[int] = None) -> None:
        self._nodes: Dict[str, Node] = {}
        self._edges: Dict[str, Edge] = {}
        self._out: Dict[str, Set[str]] = defaultdict(set)   # node_id -> set(edge_id)
        self._in: Dict[str, Set[str]] = defaultdict(set)    # node_id -> set(edge_id)
        self._hooks: Dict[str, List[Callable[..., None]]] = defaultdict(list)
        self._metrics = GraphMetrics()
        self._lock = threading.RLock()
        self._seed = seed if seed is not None else 1337
        self._rng = random.Random(self._seed)

    # ------------- hooks -------------
    def on(self, event: str, handler: Callable[..., None]) -> None:
        """Register sync hook. Events: node_added, node_removed, edge_added, edge_removed, node_updated."""
        with self._lock:
            self._hooks[event].append(handler)

    def _emit(self, event: str, **kwargs: Any) -> None:
        for h in list(self._hooks.get(event, ())):
            try:
                h(**kwargs)
            except Exception:
                # Hooks must not break graph operations in tests
                pass

    # ------------- add/remove/update -------------
    def add_node(self, node_id: str, *, label: str = "node", props: Optional[Dict[str, Any]] = None, tx: Optional[GraphTransaction] = None) -> Node:
        with self._lock:
            if node_id in self._nodes:
                raise NodeExistsError(f"Node '{node_id}' already exists")
            node = Node(id=node_id, label=label, props=dict(props or {}))
            self._unsafe_add_node(node)
            if tx:
                tx.record("del_node", node)
            self._metrics.nodes_added += 1
            self._emit("node_added", node=node)
            return node

    def _unsafe_add_node(self, node: Node) -> None:
        self._nodes[node.id] = node

    def set_node_props(self, node_id: str, **updates: Any) -> Node:
        with self._lock:
            n = self._nodes.get(node_id)
            if not n:
                raise NodeNotFoundError(node_id)
            old = n
            new = n.with_props(**updates)
            self._unsafe_set_node(new)
            self._metrics.queries_total += 1
            self._emit("node_updated", old=old, new=new)
            return new

    def _unsafe_set_node(self, node: Node) -> None:
        self._nodes[node.id] = node

    def remove_node(self, node_id: str, tx: Optional[GraphTransaction] = None) -> None:
        with self._lock:
            if node_id not in self._nodes:
                raise NodeNotFoundError(node_id)
            # store node for undo
            node = self._nodes[node_id]
            # capture incident edges for undo
            incident_edges = list(self._out[node_id] | self._in[node_id])
            if tx:
                tx.record("del_node", node)
                for eid in incident_edges:
                    tx.record("del_edge", self._edges[eid])
            # remove incident edges
            for eid in incident_edges:
                self._unsafe_remove_edge(eid)
                self._metrics.edges_removed += 1
                self._emit("edge_removed", edge_id=eid)
            # remove node
            self._unsafe_remove_node(node_id)
            self._metrics.nodes_removed += 1
            self._emit("node_removed", node_id=node_id)

    def _unsafe_remove_node(self, node_id: str) -> None:
        self._nodes.pop(node_id, None)
        for e in list(self._out[node_id]):
            self._out[node_id].discard(e)
        for e in list(self._in[node_id]):
            self._in[node_id].discard(e)
        self._out.pop(node_id, None)
        self._in.pop(node_id, None)

    def add_edge(
        self,
        edge_id: Optional[str],
        src: str,
        dst: str,
        *,
        label: str = "edge",
        weight: float = 1.0,
        props: Optional[Dict[str, Any]] = None,
        tx: Optional[GraphTransaction] = None,
    ) -> Edge:
        with self._lock:
            if src not in self._nodes or dst not in self._nodes:
                raise NodeNotFoundError("src/dst must exist")
            eid = edge_id or self._gen_edge_id(src, dst)
            if eid in self._edges:
                # regenerate until unique for auto ids
                if edge_id is None:
                    eid = self._gen_edge_id(src, dst, salt=str(self._rng.random()))
                else:
                    raise EdgeNotFoundError(f"Edge '{eid}' already exists")
            edge = Edge(id=eid, src=src, dst=dst, label=label, weight=float(weight), props=dict(props or {}))
            self._unsafe_add_edge(edge)
            if tx:
                tx.record("del_edge", edge)
            self._metrics.edges_added += 1
            self._emit("edge_added", edge=edge)
            return edge

    def _unsafe_add_edge(self, edge: Edge) -> None:
        self._edges[edge.id] = edge
        self._out[edge.src].add(edge.id)
        self._in[edge.dst].add(edge.id)

    def _unsafe_remove_edge(self, edge_id: str) -> None:
        e = self._edges.pop(edge_id, None)
        if not e:
            return
        self._out[e.src].discard(edge_id)
        self._in[e.dst].discard(edge_id)

    def remove_edge(self, edge_id: str, tx: Optional[GraphTransaction] = None) -> None:
        with self._lock:
            edge = self._edges.get(edge_id)
            if not edge:
                raise EdgeNotFoundError(edge_id)
            if tx:
                tx.record("del_edge", edge)
            self._unsafe_remove_edge(edge_id)
            self._metrics.edges_removed += 1
            self._emit("edge_removed", edge_id=edge_id)

    def set_edge_weight(self, edge_id: str, weight: float, tx: Optional[GraphTransaction] = None) -> Edge:
        with self._lock:
            e = self._edges.get(edge_id)
            if not e:
                raise EdgeNotFoundError(edge_id)
            if tx:
                tx.record("set_weight", (edge_id, e.weight))
            new_e = Edge(id=e.id, src=e.src, dst=e.dst, label=e.label, weight=float(weight), props=dict(e.props))
            self._edges[edge_id] = new_e
            self._emit("edge_updated", old=e, new=new_e)
            return new_e

    def _unsafe_set_edge_weight(self, edge_id: str, old_weight: float) -> None:
        e = self._edges.get(edge_id)
        if e:
            self._edges[edge_id] = Edge(id=e.id, src=e.src, dst=e.dst, label=e.label, weight=float(old_weight), props=dict(e.props))

    # ------------- accessors -------------
    def node(self, node_id: str) -> Node:
        n = self._nodes.get(node_id)
        if not n:
            raise NodeNotFoundError(node_id)
        return n

    def edge(self, edge_id: str) -> Edge:
        e = self._edges.get(edge_id)
        if not e:
            raise EdgeNotFoundError(edge_id)
        return e

    def nodes(self, *, label: Optional[str] = None) -> List[Node]:
        vs = list(self._nodes.values())
        return [n for n in vs if label is None or n.label == label]

    def edges(self, *, label: Optional[str] = None) -> List[Edge]:
        es = list(self._edges.values())
        return [e for e in es if label is None or e.label == label]

    def neighbors_out(self, node_id: str) -> List[str]:
        if node_id not in self._nodes:
            raise NodeNotFoundError(node_id)
        return [self._edges[eid].dst for eid in self._out[node_id]]

    def neighbors_in(self, node_id: str) -> List[str]:
        if node_id not in self._nodes:
            raise NodeNotFoundError(node_id)
        return [self._edges[eid].src for eid in self._in[node_id]]

    def degree(self, node_id: str) -> Tuple[int, int]:
        return (len(self._out.get(node_id, ())), len(self._in.get(node_id, ())))

    # ------------- queries -------------
    def bfs(self, start: str, *, max_depth: Optional[int] = None) -> List[str]:
        t0 = time.perf_counter()
        try:
            if start not in self._nodes:
                raise NodeNotFoundError(start)
            q = deque([start])
            seen: Set[str] = {start}
            depth: Dict[str, int] = {start: 0}
            order: List[str] = []
            while q:
                v = q.popleft()
                order.append(v)
                if max_depth is not None and depth[v] >= max_depth:
                    continue
                for eid in self._out.get(v, ()):
                    u = self._edges[eid].dst
                    if u not in seen:
                        seen.add(u)
                        depth[u] = depth[v] + 1
                        q.append(u)
            return order
        finally:
            self._record_query_latency(t0)

    def shortest_path(self, src: str, dst: str) -> Tuple[float, List[str]]:
        """Dijkstra by edge.weight; returns (total_weight, path node ids)."""
        t0 = time.perf_counter()
        try:
            if src not in self._nodes or dst not in self._nodes:
                raise NodeNotFoundError("src/dst must exist")
            dist: Dict[str, float] = defaultdict(lambda: math.inf)
            prev: Dict[str, Optional[str]] = {}
            dist[src] = 0.0
            visited: Set[str] = set()
            # Simple O(V^2) since graphs are moderate for tests
            while True:
                # pick unvisited with smallest dist
                u = None
                best = math.inf
                for n in self._nodes.keys():
                    if n in visited:
                        continue
                    if dist[n] < best:
                        u, best = n, dist[n]
                if u is None or u == dst:
                    break
                visited.add(u)
                for eid in self._out.get(u, ()):
                    e = self._edges[eid]
                    alt = dist[u] + max(0.0, float(e.weight))
                    if alt < dist[e.dst]:
                        dist[e.dst] = alt
                        prev[e.dst] = u
            if dist[dst] is math.inf:
                return (math.inf, [])
            # reconstruct
            path: List[str] = []
            cur: Optional[str] = dst
            while cur is not None:
                path.append(cur)
                cur = prev.get(cur)
            path.reverse()
            return (dist[dst], path)
        finally:
            self._record_query_latency(t0)

    def subgraph_by_labels(self, node_labels: Optional[Set[str]] = None, edge_labels: Optional[Set[str]] = None) -> "GraphMock":
        t0 = time.perf_counter()
        try:
            g = GraphMock(seed=self._seed)
            with g.tx() as _:
                for n in self._nodes.values():
                    if node_labels is None or n.label in node_labels:
                        g.add_node(n.id, label=n.label, props=dict(n.props))
                for e in self._edges.values():
                    if (edge_labels is None or e.label in edge_labels) and e.src in g._nodes and e.dst in g._nodes:
                        g.add_edge(e.id, e.src, e.dst, label=e.label, weight=e.weight, props=dict(e.props))
            return g
        finally:
            self._record_query_latency(t0)

    def find_nodes(self, predicate: Callable[[Node], bool]) -> List[Node]:
        t0 = time.perf_counter()
        try:
            return [n for n in self._nodes.values() if predicate(n)]
        finally:
            self._record_query_latency(t0)

    # ------------- serialization -------------
    def to_json(self) -> str:
        with self._lock:
            data = {
                "nodes": [asdict(n) for n in sorted(self._nodes.values(), key=lambda x: x.id)],
                "edges": [asdict(e) for e in sorted(self._edges.values(), key=lambda x: x.id)],
                "meta": {"seed": self._seed},
            }
            return json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    @staticmethod
    def from_json(blob: Union[str, bytes]) -> "GraphMock":
        data = json.loads(blob)
        g = GraphMock(seed=int(data.get("meta", {}).get("seed", 1337)))
        with g.tx():
            for n in data.get("nodes", []):
                g.add_node(n["id"], label=n.get("label", "node"), props=n.get("props", {}))
            for e in data.get("edges", []):
                g.add_edge(e.get("id"), e["src"], e["dst"], label=e.get("label", "edge"), weight=float(e.get("weight", 1.0)), props=e.get("props", {}))
        return g

    # ------------- deterministic generation -------------
    def generate_grid(self, rows: int, cols: int, *, label: str = "grid", bidir: bool = True) -> None:
        """Generate rows x cols grid graph with deterministic ids."""
        with self.tx():
            for r in range(rows):
                for c in range(cols):
                    nid = f"{label}:{r}:{c}"
                    self.add_node(nid, label=label, props={"row": r, "col": c})
            for r in range(rows):
                for c in range(cols):
                    src = f"{label}:{r}:{c}"
                    if c + 1 < cols:
                        dst = f"{label}:{r}:{c+1}"
                        self.add_edge(None, src, dst, label="grid_right", weight=1.0)
                        if bidir:
                            self.add_edge(None, dst, src, label="grid_left", weight=1.0)
                    if r + 1 < rows:
                        dst = f"{label}:{r+1}:{c}"
                        self.add_edge(None, src, dst, label="grid_down", weight=1.0)
                        if bidir:
                            self.add_edge(None, dst, src, label="grid_up", weight=1.0)

    def generate_random(self, n_nodes: int, n_edges: int, *, node_label: str = "node", edge_label: str = "edge") -> None:
        with self.tx():
            for i in range(n_nodes):
                self.add_node(f"{node_label}:{i}", label=node_label, props={"i": i})
            ids = [f"{node_label}:{i}" for i in range(n_nodes)]
            for _ in range(n_edges):
                a, b = self._rng.choice(ids), self._rng.choice(ids)
                if a == b:
                    continue
                w = round(self._rng.uniform(0.1, 5.0), 3)
                self.add_edge(None, a, b, label=edge_label, weight=w, props={"rnd": True})

    # ------------- transactions -------------
    @contextmanager
    def tx(self) -> Iterator[GraphTransaction]:
        tx = GraphTransaction()
        try:
            yield tx
        except Exception:
            with self._lock:
                tx.rollback(self)
                self._metrics.tx_rolled_back += 1
            raise
        else:
            with self._lock:
                tx.active = False
                self._metrics.tx_committed += 1

    # ------------- internals -------------
    def _gen_edge_id(self, src: str, dst: str, *, salt: Optional[str] = None) -> str:
        base = f"{src}->{dst}"
        if salt is not None:
            base += f"#{salt}"
        return f"e:{abs(hash(base))}"

    def _record_query_latency(self, t0: float) -> None:
        dt = (time.perf_counter() - t0) * 1000.0
        self._metrics.queries_total += 1
        self._metrics.last_query_ms = dt

    # ------------- meta -------------
    def metrics(self) -> Dict[str, Any]:
        return self._metrics.snapshot()

    def clear(self) -> None:
        with self._lock:
            self._nodes.clear()
            self._edges.clear()
            self._out.clear()
            self._in.clear()

# ----------------------------
# Async wrapper (uses a single-threaded executor for heavy ops if needed)
# ----------------------------
class AsyncGraphMock:
    def __init__(self, base: Optional[GraphMock] = None) -> None:
        self._g = base or GraphMock()
        self._lock = asyncio.Lock()

    async def add_node(self, node_id: str, **kw: Any) -> Node:
        async with self._lock:
            return self._g.add_node(node_id, **kw)

    async def add_edge(self, edge_id: Optional[str], src: str, dst: str, **kw: Any) -> Edge:
        async with self._lock:
            return self._g.add_edge(edge_id, src, dst, **kw)

    async def remove_node(self, node_id: str) -> None:
        async with self._lock:
            return self._g.remove_node(node_id)

    async def remove_edge(self, edge_id: str) -> None:
        async with self._lock:
            return self._g.remove_edge(edge_id)

    async def set_edge_weight(self, edge_id: str, weight: float) -> Edge:
        async with self._lock:
            return self._g.set_edge_weight(edge_id, weight)

    async def node(self, node_id: str) -> Node:
        async with self._lock:
            return self._g.node(node_id)

    async def neighbors_out(self, node_id: str) -> List[str]:
        async with self._lock:
            return self._g.neighbors_out(node_id)

    async def neighbors_in(self, node_id: str) -> List[str]:
        async with self._lock:
            return self._g.neighbors_in(node_id)

    async def bfs(self, start: str, *, max_depth: Optional[int] = None) -> List[str]:
        async with self._lock:
            return self._g.bfs(start, max_depth=max_depth)

    async def shortest_path(self, src: str, dst: str) -> Tuple[float, List[str]]:
        async with self._lock:
            return self._g.shortest_path(src, dst)

    async def to_json(self) -> str:
        async with self._lock:
            return self._g.to_json()

    async def metrics(self) -> Dict[str, Any]:
        async with self._lock:
            return self._g.metrics()
