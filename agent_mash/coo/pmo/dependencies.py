# agent_mash/pmo/dependencies.py
# Industrial-grade dependency graph for PMO / workforce routing.
# Features:
# - Typed dependency edges (FS/SS/FF/SF + custom)
# - Strict validation and cycle detection
# - Topological ordering (Kahn) with deterministic tie-breaking
# - Critical path estimation using durations
# - Readiness checks and blocking reasons
# - Impact analysis (what becomes blocked/unblocked)
# - Mermaid export for audit / visualization
# - JSON-safe serialization
#
# No external dependencies.

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple


__all__ = [
    "DependencyError",
    "DependencyValidationError",
    "DependencyCycleError",
    "WorkStatus",
    "EdgeType",
    "WorkItem",
    "DependencyEdge",
    "DependencyGraph",
    "BlockingReason",
]


def _now_ms() -> int:
    return int(time.time() * 1000)


def _ensure_jsonable(value: Any, *, path: str = "$") -> None:
    try:
        json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    except TypeError as e:
        raise DependencyValidationError(f"Non-JSON-serializable value at {path}: {e}") from e


def _stable_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class DependencyError(RuntimeError):
    """Base error for PMO dependency subsystem."""


class DependencyValidationError(DependencyError):
    """Graph or item validation failed."""


class DependencyCycleError(DependencyError):
    """A cycle exists in a graph that is expected to be acyclic."""


class WorkStatus(str, Enum):
    """
    Canonical work statuses for PMO.
    Routing typically considers READY only when blockers are cleared.
    """
    NEW = "new"
    READY = "ready"
    RUNNING = "running"
    BLOCKED = "blocked"
    DONE = "done"
    FAILED = "failed"
    CANCELED = "canceled"
    ARCHIVED = "archived"


class EdgeType(str, Enum):
    """
    Common scheduling dependency semantics:
    - FS: finish-to-start (default): successor can start after predecessor finishes
    - SS: start-to-start: successor can start after predecessor starts
    - FF: finish-to-finish: successor can finish after predecessor finishes
    - SF: start-to-finish: successor can finish after predecessor starts
    - HARD: must be fully satisfied regardless of scheduling semantics (acts like FS for readiness)
    """
    FS = "FS"
    SS = "SS"
    FF = "FF"
    SF = "SF"
    HARD = "HARD"


@dataclass(frozen=True, slots=True)
class WorkItem:
    """
    Work item node for dependency graph.

    Fields:
    - id: unique within graph (stable, human-readable is fine)
    - title: short name
    - status: lifecycle status
    - duration_ms: optional estimate for critical path
    - tags/meta: optional json-safe details
    """
    id: str
    title: str
    status: WorkStatus = WorkStatus.NEW
    duration_ms: int = 0
    tags: Tuple[str, ...] = ()
    meta: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id or not isinstance(self.id, str):
            raise DependencyValidationError("WorkItem.id must be non-empty string")
        if not self.title or not isinstance(self.title, str):
            raise DependencyValidationError("WorkItem.title must be non-empty string")
        if not isinstance(self.duration_ms, int) or self.duration_ms < 0:
            raise DependencyValidationError("WorkItem.duration_ms must be non-negative int")
        if not isinstance(self.tags, tuple) or any((not isinstance(t, str) or not t) for t in self.tags):
            raise DependencyValidationError("WorkItem.tags must be tuple[str, ...] of non-empty strings")
        _ensure_jsonable(dict(self.meta), path=f"$.work_items[{self.id}].meta")


@dataclass(frozen=True, slots=True)
class DependencyEdge:
    """
    Dependency edge between two work items.

    predecessor -> successor

    - type: EdgeType semantics
    - lag_ms: optional lag/offset (mainly for scheduling/visualization)
    - hard: if True, readiness uses DONE predicate (acts like FS/HARD)
    """
    predecessor: str
    successor: str
    type: EdgeType = EdgeType.FS
    lag_ms: int = 0
    hard: bool = True
    meta: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.predecessor or not isinstance(self.predecessor, str):
            raise DependencyValidationError("DependencyEdge.predecessor must be non-empty string")
        if not self.successor or not isinstance(self.successor, str):
            raise DependencyValidationError("DependencyEdge.successor must be non-empty string")
        if self.predecessor == self.successor:
            raise DependencyValidationError("Self-loop dependency is not allowed")
        if not isinstance(self.lag_ms, int) or self.lag_ms < 0:
            raise DependencyValidationError("DependencyEdge.lag_ms must be non-negative int")
        if not isinstance(self.hard, bool):
            raise DependencyValidationError("DependencyEdge.hard must be bool")
        _ensure_jsonable(dict(self.meta), path="$.edge.meta")

    def key(self) -> str:
        base = f"{self.predecessor}|{self.type.value}|{self.successor}|{self.lag_ms}|{int(self.hard)}"
        return _stable_hash(base)


@dataclass(frozen=True, slots=True)
class BlockingReason:
    """
    Explains why a work item is not ready.
    """
    item_id: str
    blocked_by: Tuple[str, ...]
    edge_keys: Tuple[str, ...]
    message: str


class DependencyGraph:
    """
    Dependency graph for PMO tasks.

    Invariants:
    - Node IDs are unique.
    - Edges reference existing nodes.
    - Graph can be treated as DAG for scheduling. Cycle detection is built-in.

    Determinism:
    - Topological ordering and exports are deterministic (sorted tie-breaks).
    """
    def __init__(self, *, graph_id: Optional[str] = None) -> None:
        self.graph_id: str = graph_id or f"pmo-{uuid4_compact()}"
        self.created_at_ms: int = _now_ms()
        self.updated_at_ms: int = self.created_at_ms

        self._items: Dict[str, WorkItem] = {}
        self._edges: Dict[str, DependencyEdge] = {}

        # adjacency
        self._out: Dict[str, Set[str]] = {}
        self._in: Dict[str, Set[str]] = {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "graph_id": self.graph_id,
            "created_at_ms": self.created_at_ms,
            "updated_at_ms": self.updated_at_ms,
            "items": [asdict(w) | {"status": w.status.value} for w in self._items.values()],
            "edges": [
                {
                    "predecessor": e.predecessor,
                    "successor": e.successor,
                    "type": e.type.value,
                    "lag_ms": e.lag_ms,
                    "hard": e.hard,
                    "meta": dict(e.meta),
                    "edge_key": k,
                }
                for k, e in self._edges.items()
            ],
        }

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "DependencyGraph":
        g = DependencyGraph(graph_id=str(d.get("graph_id") or f"pmo-{uuid4_compact()}"))
        g.created_at_ms = int(d.get("created_at_ms", _now_ms()))
        g.updated_at_ms = int(d.get("updated_at_ms", g.created_at_ms))

        items = d.get("items", [])
        if not isinstance(items, list):
            raise DependencyValidationError("items must be list")
        for it in items:
            if not isinstance(it, dict):
                raise DependencyValidationError("item must be dict")
            status_val = it.get("status", WorkStatus.NEW.value)
            w = WorkItem(
                id=str(it["id"]),
                title=str(it["title"]),
                status=WorkStatus(str(status_val)),
                duration_ms=int(it.get("duration_ms", 0)),
                tags=tuple(it.get("tags", ())),
                meta=dict(it.get("meta", {})),
            )
            g.add_item(w)

        edges = d.get("edges", [])
        if not isinstance(edges, list):
            raise DependencyValidationError("edges must be list")
        for ed in edges:
            if not isinstance(ed, dict):
                raise DependencyValidationError("edge must be dict")
            et = EdgeType(str(ed.get("type", EdgeType.FS.value)))
            e = DependencyEdge(
                predecessor=str(ed["predecessor"]),
                successor=str(ed["successor"]),
                type=et,
                lag_ms=int(ed.get("lag_ms", 0)),
                hard=bool(ed.get("hard", True)),
                meta=dict(ed.get("meta", {})),
            )
            g.add_edge(e)

        return g

    def items(self) -> Mapping[str, WorkItem]:
        return dict(self._items)

    def edges(self) -> Mapping[str, DependencyEdge]:
        return dict(self._edges)

    def add_item(self, item: WorkItem) -> None:
        if item.id in self._items:
            raise DependencyValidationError(f"Duplicate WorkItem id: {item.id}")
        self._items[item.id] = item
        self._out[item.id] = set()
        self._in[item.id] = set()
        self._touch()

    def upsert_item(self, item: WorkItem) -> None:
        if item.id not in self._items:
            self.add_item(item)
            return
        self._items[item.id] = item
        self._touch()

    def remove_item(self, item_id: str, *, cascade_edges: bool = True) -> None:
        if item_id not in self._items:
            return
        if cascade_edges:
            # remove inbound edges
            for pred in sorted(self._in.get(item_id, set())):
                self.remove_edge_by_nodes(pred, item_id)
            # remove outbound edges
            for succ in sorted(self._out.get(item_id, set())):
                self.remove_edge_by_nodes(item_id, succ)
        else:
            if self._in.get(item_id) or self._out.get(item_id):
                raise DependencyValidationError("Cannot remove item with connected edges unless cascade_edges=True")

        self._items.pop(item_id, None)
        self._out.pop(item_id, None)
        self._in.pop(item_id, None)
        self._touch()

    def add_edge(self, edge: DependencyEdge) -> str:
        if edge.predecessor not in self._items:
            raise DependencyValidationError(f"Edge predecessor not found: {edge.predecessor}")
        if edge.successor not in self._items:
            raise DependencyValidationError(f"Edge successor not found: {edge.successor}")

        k = edge.key()
        if k in self._edges:
            return k

        self._edges[k] = edge
        self._out[edge.predecessor].add(edge.successor)
        self._in[edge.successor].add(edge.predecessor)
        self._touch()
        return k

    def remove_edge(self, edge_key: str) -> None:
        e = self._edges.pop(edge_key, None)
        if e is None:
            return
        self._out.get(e.predecessor, set()).discard(e.successor)
        self._in.get(e.successor, set()).discard(e.predecessor)
        self._touch()

    def remove_edge_by_nodes(self, predecessor: str, successor: str) -> None:
        to_remove: List[str] = []
        for k, e in self._edges.items():
            if e.predecessor == predecessor and e.successor == successor:
                to_remove.append(k)
        for k in to_remove:
            self.remove_edge(k)

    def predecessors(self, item_id: str) -> Tuple[str, ...]:
        return tuple(sorted(self._in.get(item_id, set())))

    def successors(self, item_id: str) -> Tuple[str, ...]:
        return tuple(sorted(self._out.get(item_id, set())))

    def validate_acyclic(self) -> None:
        cycles = self.find_cycles(limit=1)
        if cycles:
            raise DependencyCycleError(f"Cycle detected: {cycles[0]}")

    def find_cycles(self, *, limit: int = 10) -> List[List[str]]:
        """
        Finds cycles using DFS recursion stack.
        Returns up to 'limit' cycles, each as a list of node ids in cycle order.
        """
        visited: Set[str] = set()
        stack: Set[str] = set()
        parent: Dict[str, str] = {}
        cycles: List[List[str]] = []

        def _reconstruct_cycle(start: str, end: str) -> List[str]:
            path = [end]
            cur = end
            while cur != start and cur in parent:
                cur = parent[cur]
                path.append(cur)
            path.reverse()
            return path

        def _dfs(u: str) -> None:
            nonlocal cycles
            visited.add(u)
            stack.add(u)
            for v in sorted(self._out.get(u, set())):
                if v not in visited:
                    parent[v] = u
                    _dfs(v)
                    if len(cycles) >= limit:
                        return
                elif v in stack:
                    cycles.append(_reconstruct_cycle(v, u) + [v])
                    if len(cycles) >= limit:
                        return
            stack.remove(u)

        for node in sorted(self._items.keys()):
            if node not in visited:
                _dfs(node)
                if len(cycles) >= limit:
                    break
        return cycles

    def topo_sort(self) -> List[str]:
        """
        Deterministic Kahn topological sort.
        Raises DependencyCycleError if cycle exists.
        """
        indeg: Dict[str, int] = {n: 0 for n in self._items.keys()}
        for succ, preds in self._in.items():
            indeg[succ] = len(preds)

        ready = sorted([n for n, d in indeg.items() if d == 0])
        out: List[str] = []
        indeg_mut = dict(indeg)

        while ready:
            u = ready.pop(0)
            out.append(u)
            for v in sorted(self._out.get(u, set())):
                indeg_mut[v] -= 1
                if indeg_mut[v] == 0:
                    ready.append(v)
                    ready.sort()

        if len(out) != len(self._items):
            raise DependencyCycleError("Topological sort failed due to cycle")
        return out

    def blocking_reason(self, item_id: str) -> Optional[BlockingReason]:
        """
        Returns blocking reason for an item (if any) based on HARD/FS semantics:
        - For readiness, a predecessor must be DONE unless:
          - edge.hard is False and edge.type in (SS, SF) may allow earlier start
        This function is conservative by design: it blocks unless clearly allowed.

        Conservative rules:
        - FS/HARD: predecessor must be DONE
        - SS with hard=False: predecessor must be STARTED (RUNNING or DONE)
        - FF with hard=False: predecessor must be STARTED (RUNNING or DONE) for routing start; DONE for finish semantics not modeled here
        - SF with hard=False: predecessor must be STARTED (RUNNING or DONE)
        """
        if item_id not in self._items:
            raise DependencyValidationError(f"Unknown item: {item_id}")

        item = self._items[item_id]
        if item.status in (WorkStatus.DONE, WorkStatus.CANCELED, WorkStatus.ARCHIVED):
            return None

        blocked_by: List[str] = []
        edge_keys: List[str] = []

        preds = self.predecessors(item_id)
        for pred in preds:
            pred_item = self._items[pred]
            for k, e in self._edges.items():
                if e.predecessor == pred and e.successor == item_id:
                    if self._edge_blocks(e, pred_item.status):
                        blocked_by.append(pred)
                        edge_keys.append(k)

        if not blocked_by:
            return None

        msg = f"Blocked by {len(blocked_by)} predecessor(s)"
        return BlockingReason(
            item_id=item_id,
            blocked_by=tuple(blocked_by),
            edge_keys=tuple(edge_keys),
            message=msg,
        )

    @staticmethod
    def _edge_blocks(edge: DependencyEdge, pred_status: WorkStatus) -> bool:
        if pred_status in (WorkStatus.CANCELED, WorkStatus.ARCHIVED):
            # conservative: treat as not satisfying unless explicitly DONE
            return True
        if edge.hard or edge.type in (EdgeType.FS, EdgeType.HARD):
            return pred_status != WorkStatus.DONE
        # soft edges
        if edge.type in (EdgeType.SS, EdgeType.SF, EdgeType.FF):
            return pred_status not in (WorkStatus.RUNNING, WorkStatus.DONE)
        return pred_status != WorkStatus.DONE

    def is_ready(self, item_id: str) -> bool:
        item = self._items.get(item_id)
        if item is None:
            raise DependencyValidationError(f"Unknown item: {item_id}")
        if item.status in (WorkStatus.DONE, WorkStatus.CANCELED, WorkStatus.ARCHIVED):
            return False
        return self.blocking_reason(item_id) is None

    def ready_items(self) -> Tuple[str, ...]:
        """
        Returns ids of items that are ready to be routed.
        Deterministic ordering by topo order, then id.
        """
        order = self.topo_sort_safe()
        ready = [i for i in order if self.is_ready(i)]
        return tuple(ready)

    def topo_sort_safe(self) -> List[str]:
        """
        Topo sort but if a cycle exists, returns a stable fallback ordering by id.
        This is for dashboards; routing should use topo_sort() and fail fast.
        """
        try:
            return self.topo_sort()
        except DependencyCycleError:
            return sorted(self._items.keys())

    def critical_path(self) -> Tuple[Tuple[str, ...], int]:
        """
        Estimates critical path length using durations (ms) in a DAG.
        Raises DependencyCycleError if cyclic.

        Returns:
        - path node ids
        - total duration ms
        """
        order = self.topo_sort()
        dist: Dict[str, int] = {n: self._items[n].duration_ms for n in order}
        prev: Dict[str, Optional[str]] = {n: None for n in order}

        for u in order:
            base = dist[u]
            for v in self.successors(u):
                cand = base + self._items[v].duration_ms
                if cand > dist[v]:
                    dist[v] = cand
                    prev[v] = u

        end = max(order, key=lambda n: dist[n]) if order else None
        if end is None:
            return ((), 0)

        path: List[str] = []
        cur: Optional[str] = end
        while cur is not None:
            path.append(cur)
            cur = prev[cur]
        path.reverse()
        return (tuple(path), dist[end])

    def impact_on_completion(self, completed_item_id: str) -> Dict[str, Any]:
        """
        Impact analysis when a single item becomes DONE:
        - which successors become newly unblocked
        - which items remain blocked and why

        Returns JSON-safe dict.
        """
        if completed_item_id not in self._items:
            raise DependencyValidationError(f"Unknown item: {completed_item_id}")

        before_ready = set(self.ready_items())
        # simulate completion
        original = self._items[completed_item_id]
        self._items[completed_item_id] = WorkItem(
            id=original.id,
            title=original.title,
            status=WorkStatus.DONE,
            duration_ms=original.duration_ms,
            tags=original.tags,
            meta=original.meta,
        )
        try:
            after_ready = set(self.ready_items())
        finally:
            self._items[completed_item_id] = original

        newly_unblocked = sorted(list(after_ready - before_ready))
        still_blocked: Dict[str, Any] = {}
        for item_id in self.successors(completed_item_id):
            br = self.blocking_reason(item_id)
            if br is not None:
                still_blocked[item_id] = {
                    "blocked_by": list(br.blocked_by),
                    "edge_keys": list(br.edge_keys),
                    "message": br.message,
                }

        out = {
            "completed": completed_item_id,
            "newly_unblocked": newly_unblocked,
            "still_blocked": still_blocked,
            "timestamp_ms": _now_ms(),
        }
        _ensure_jsonable(out, path="$.impact_on_completion")
        return out

    def export_mermaid(self, *, title: Optional[str] = None) -> str:
        """
        Mermaid flowchart export (deterministic).
        """
        t = title or f"PMO Dependencies {self.graph_id}"
        lines: List[str] = []
        lines.append("flowchart TD")
        lines.append(f'  %% {t}')

        # nodes
        for item_id in sorted(self._items.keys()):
            w = self._items[item_id]
            label = _escape_mermaid(f"{w.title} [{w.status.value}]")
            lines.append(f'  {self._mnode(item_id)}["{label}"]')

        # edges
        for k in sorted(self._edges.keys()):
            e = self._edges[k]
            edge_label = f"{e.type.value}"
            if e.lag_ms:
                edge_label += f"+{e.lag_ms}ms"
            if e.hard:
                edge_label += "|hard"
            edge_label = _escape_mermaid(edge_label)
            lines.append(f"  {self._mnode(e.predecessor)} -->|{edge_label}| {self._mnode(e.successor)}")

        return "\n".join(lines)

    def _mnode(self, item_id: str) -> str:
        # Mermaid node ids must avoid certain chars. We make a stable safe node id.
        return "W_" + _stable_hash(item_id)[:12]

    def _touch(self) -> None:
        self.updated_at_ms = _now_ms()

    def snapshot(self) -> Dict[str, Any]:
        snap = self.to_dict()
        _ensure_jsonable(snap, path="$.snapshot")
        return snap

    def restore(self, snapshot: Mapping[str, Any]) -> None:
        g = DependencyGraph.from_dict(snapshot)
        self.graph_id = g.graph_id
        self.created_at_ms = g.created_at_ms
        self.updated_at_ms = g.updated_at_ms
        self._items = dict(g._items)
        self._edges = dict(g._edges)
        self._out = {k: set(v) for k, v in g._out.items()}
        self._in = {k: set(v) for k, v in g._in.items()}


def _escape_mermaid(text: str) -> str:
    # Keep it safe in quotes
    return (
        text.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", " ")
        .replace("\r", " ")
    )


def uuid4_compact() -> str:
    # Local compact UUID generator without importing uuid to keep dependencies minimal in some environments.
    # Uses time and sha256; uniqueness is sufficient for graph IDs in-process.
    seed = f"{time.time_ns()}|{os_getpid_safe()}|{_now_ms()}"
    return _stable_hash(seed)[:16]


def os_getpid_safe() -> int:
    try:
        import os
        return int(os.getpid())
    except Exception:
        return 0
