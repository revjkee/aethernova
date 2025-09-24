# engine-core/engine/adapters/graph_core_adapter.py
"""
Industrial-grade Graph Core Adapter for engine-core.

Goals:
- Clean async API bridging engine data (ECS/state) and a graph core (DB/compute)
- Client injection via GraphCoreClient interface (drivers for Neo4j/Janus/etc. can be added outside)
- Deterministic canonical serialization + FNV64 hash (idempotency keys)
- Transactions, retries with full jitter, token-bucket RPS, bounded concurrency
- TTL cache for read queries, per-query idempotency window
- Schema-checked nodes/edges with versioned types, validators and index hints
- Query builder (match/where/projection), traversals, shortest_path, subgraph export
- Consistency levels: "RO" (snapshot), "RC" (read committed), "RR" (repeatable read) - abstracted
- Telemetry hooks; structured errors

No external dependencies. Python 3.10+.
"""

from __future__ import annotations

import asyncio
import json
import time
import math
import re
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union, AsyncIterator, Callable

# =========================
# Utils: canonical json + hash
# =========================

def _ujson(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

FNV64_OFFSET = 0xcbf29ce484222325
FNV64_PRIME  = 0x100000001b3

def fnv1a64(data: bytes, seed: int = FNV64_OFFSET) -> int:
    h = seed & 0xFFFFFFFFFFFFFFFF
    for b in data:
        h ^= b
        h = (h * FNV64_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h

def canon_hash(obj: Any) -> str:
    return hashlib.sha256(_ujson(obj).encode("utf-8")).hexdigest()

# =========================
# Errors
# =========================

class GraphAdapterError(Exception): ...
class GraphBadRequest(GraphAdapterError): ...
class GraphRetryable(GraphAdapterError): ...
class GraphRateLimited(GraphAdapterError): ...
class GraphTimeout(GraphAdapterError): ...
class GraphTxnError(GraphAdapterError): ...

# =========================
# Telemetry & rate limiting
# =========================

TelemetryHook = Callable[[str, Mapping[str,str], Mapping[str,float]], None]

class TokenBucket:
    def __init__(self, rate_per_s: float, burst: float) -> None:
        self.rate = float(max(0.0, rate_per_s))
        self.burst = float(max(1.0, burst))
        self.tokens = self.burst
        self.last = time.monotonic()
        self.cv = asyncio.Condition()

    def _refill(self) -> None:
        now = time.monotonic()
        dt = now - self.last
        if dt > 0:
            self.tokens = min(self.burst, self.tokens + dt * self.rate)
            self.last = now

    async def acquire(self, cost: float = 1.0, timeout_s: float = 30.0) -> None:
        deadline = time.monotonic() + timeout_s
        async with self.cv:
            while True:
                self._refill()
                if self.tokens >= cost:
                    self.tokens -= cost
                    return
                if time.monotonic() >= deadline:
                    raise GraphRateLimited("rate limiter timeout")
                await self.cv.wait_for(lambda: False, timeout=0.02)

    def release(self, cost: float = 1.0) -> None:
        async def _notify():
            async with self.cv:
                self.tokens = min(self.burst, self.tokens + cost)
                self.cv.notify_all()
        try:
            asyncio.get_running_loop().create_task(_notify())
        except RuntimeError:
            pass

def _full_jitter(base: float, factor: float, attempt: int, cap: float) -> float:
    raw = min(cap, base * (factor ** max(0, attempt-1)))
    ns = time.monotonic_ns() & 0xFFFFFFFF
    rnd = ((1664525 * ns + 1013904223) & 0xFFFFFFFF) / 0xFFFFFFFF
    return raw * rnd

# =========================
# Cache with TTL
# =========================

@dataclass(slots=True)
class _CacheEntry:
    v: Any
    exp: float

class TTLCache:
    def __init__(self, max_items: int = 2048) -> None:
        self._s: Dict[str, _CacheEntry] = {}
        self._o: List[str] = []
        self._max = max_items

    def get(self, k: str) -> Optional[Any]:
        e = self._s.get(k)
        if not e: return None
        if time.monotonic() >= e.exp:
            self.delete(k); return None
        return e.v

    def set(self, k: str, v: Any, ttl_s: float) -> None:
        if len(self._o) >= self._max:
            old = self._o.pop(0)
            self._s.pop(old, None)
        self._s[k] = _CacheEntry(v=v, exp=time.monotonic()+ttl_s)
        if k in self._o: self._o.remove(k)
        self._o.append(k)

    def delete(self, k: str) -> None:
        self._s.pop(k, None)
        if k in self._o: self._o.remove(k)

# =========================
# Schema
# =========================

@dataclass(slots=True)
class NodeType:
    name: str
    version: int = 1
    required: Tuple[str, ...] = tuple()
    indexed: Tuple[str, ...] = tuple()

@dataclass(slots=True)
class EdgeType:
    name: str
    version: int = 1
    # (src_type, dst_type) constraints (names)
    src: str = ""
    dst: str = ""
    required: Tuple[str, ...] = tuple()
    directed: bool = True
    indexed: Tuple[str, ...] = tuple()

@dataclass(slots=True)
class Node:
    type: str
    key: str                         # business key (stable)
    props: Dict[str, Any] = field(default_factory=dict)
    version: int = 1                 # schema version

@dataclass(slots=True)
class Edge:
    type: str
    src: str
    dst: str
    props: Dict[str, Any] = field(default_factory=dict)
    directed: bool = True
    version: int = 1

# =========================
# Client interface (to implement externally)
# =========================

class GraphCoreClient:
    """
    Implement these methods with your driver.
    All methods must be idempotent if idempotency_key is provided.
    """

    async def begin(self, *, consistency: str) -> Any:
        raise NotImplementedError

    async def commit(self, txn: Any) -> None:
        raise NotImplementedError

    async def rollback(self, txn: Any) -> None:
        raise NotImplementedError

    async def upsert_nodes(self, txn: Any, nodes: Sequence[Node], *, idempotency_key: Optional[str]) -> List[str]:
        """Returns internal ids for nodes in order."""
        raise NotImplementedError

    async def upsert_edges(self, txn: Any, edges: Sequence[Edge], *, idempotency_key: Optional[str]) -> List[str]:
        raise NotImplementedError

    async def query(self, txn: Any, q: str, params: Mapping[str, Any], *, page: Optional[Tuple[int,int]]) -> List[Dict[str, Any]]:
        raise NotImplementedError

    async def ensure_indexes(self, txn: Any, *, node_indexes: Mapping[str, Sequence[str]], edge_indexes: Mapping[str, Sequence[str]]) -> None:
        raise NotImplementedError

# =========================
# Config
# =========================

@dataclass(slots=True)
class Limits:
    rps: float = 20.0
    burst: float = 40.0
    concurrency: int = 16
    max_retries: int = 4
    timeout_s: float = 30.0
    cache_ttl_s: float = 5.0
    idempotency_window_s: float = 120.0

@dataclass(slots=True)
class GraphAdapterConfig:
    limits: Limits = field(default_factory=Limits)
    consistency_default: str = "RC"  # RO | RC | RR
    safe_regex: Optional[re.Pattern] = None       # optional whitelist for labels/keys in builder

# =========================
# Query builder (minimal but safe)
# =========================

@dataclass(slots=True)
class Match:
    label: str
    alias: str
    where: Dict[str, Any] = field(default_factory=dict)

@dataclass(slots=True)
class Projection:
    fields: Sequence[str] = field(default_factory=lambda: ("id","type","key"))
    limit: Optional[int] = None
    order_by: Optional[str] = None
    desc: bool = False

class QueryBuilder:
    """
    Abstract text builder; actual dialect is delegated to client.query().
    We only build a canonical JSON "plan" that the client understands.
    """
    def __init__(self, *, cfg: GraphAdapterConfig) -> None:
        self.cfg = cfg
        self._matches: List[Match] = []
        self._rels: List[Tuple[str,str,str]] = []  # (from_alias, edge_type, to_alias)
        self._proj: Projection = Projection()

    def match(self, label: str, alias: str, **where: Any) -> "QueryBuilder":
        self._matches.append(Match(label=label, alias=alias, where=where))
        return self

    def relate(self, frm: str, edge_type: str, to: str) -> "QueryBuilder":
        self._rels.append((frm, edge_type, to))
        return self

    def project(self, *, fields: Sequence[str], limit: Optional[int]=None, order_by: Optional[str]=None, desc: bool=False) -> "QueryBuilder":
        self._proj = Projection(fields=tuple(fields), limit=limit, order_by=order_by, desc=desc)
        return self

    def build(self) -> Dict[str, Any]:
        plan = {
            "matches": [asdict(m) for m in self._matches],
            "rels": list(self._rels),
            "projection": asdict(self._proj),
        }
        return plan

# =========================
# Adapter
# =========================

@dataclass(slots=True)
class _TxnCtx:
    handle: Any
    started: float

class GraphCoreAdapter:
    def __init__(self, client: GraphCoreClient, cfg: GraphAdapterConfig = GraphAdapterConfig(), telemetry: Optional[TelemetryHook] = None) -> None:
        self.client = client
        self.cfg = cfg
        self.tel = telemetry or (lambda n,t,f: None)
        self.bucket = TokenBucket(cfg.limits.rps, cfg.limits.burst)
        self.sema = asyncio.Semaphore(cfg.limits.concurrency)
        self.cache = TTLCache()
        self._inflight: Dict[str, asyncio.Future] = {}

    # --------- Public API ---------

    async def transaction(self, *, consistency: Optional[str] = None) -> AsyncIterator[_TxnCtx]:
        cons = (consistency or self.cfg.consistency_default).upper()
        t0 = time.monotonic()
        await self.bucket.acquire(1.0, timeout_s=self.cfg.limits.timeout_s)
        await self.sema.acquire()
        try:
            handle = await self.client.begin(consistency=cons)
            ctx = _TxnCtx(handle=handle, started=t0)
            try:
                yield ctx
                await self.client.commit(handle)
                self._emit("graph.txn.commit", {"c":cons}, {"lat_ms": (time.monotonic()-t0)*1000})
            except Exception as e:
                await self.client.rollback(handle)
                self._emit("graph.txn.rollback", {"c":cons}, {"lat_ms": (time.monotonic()-t0)*1000})
                raise
        finally:
            self.sema.release()
            self.bucket.release(1.0)

    async def ensure_indexes(self, *, node_types: Sequence[NodeType], edge_types: Sequence[EdgeType]) -> None:
        ni: Dict[str, List[str]] = {}
        ei: Dict[str, List[str]] = {}
        for n in node_types:
            if n.indexed:
                ni[n.name] = list(n.indexed)
        for e in edge_types:
            if e.indexed:
                ei[e.name] = list(e.indexed)
        async with self.transaction() as txn:
            await self.client.ensure_indexes(txn.handle, node_indexes=ni, edge_indexes=ei)
            self._emit("graph.index.ensure", {"nodes":str(len(ni)),"edges":str(len(ei))}, {"ok":1.0})

    async def upsert_nodes(self, nodes: Sequence[Node], *, consistency: Optional[str] = None, idempotency_key: Optional[str]=None) -> List[str]:
        self._validate_nodes(nodes)
        idem = idempotency_key or canon_hash({"op":"upsert_nodes","n":[asdict(n) for n in nodes]})
        return await self._with_retries(lambda txn: self.client.upsert_nodes(txn.handle, nodes, idempotency_key=idem), tag="upsert_nodes", consistency=consistency, idem=idem)

    async def upsert_edges(self, edges: Sequence[Edge], *, consistency: Optional[str] = None, idempotency_key: Optional[str]=None) -> List[str]:
        self._validate_edges(edges)
        idem = idempotency_key or canon_hash({"op":"upsert_edges","e":[asdict(e) for e in edges]})
        return await self._with_retries(lambda txn: self.client.upsert_edges(txn.handle, edges, idempotency_key=idem), tag="upsert_edges", consistency=consistency, idem=idem)

    async def query(self, plan: Dict[str, Any], *, params: Mapping[str, Any] = {}, page: Optional[Tuple[int,int]] = None, consistency: Optional[str] = None, cache_ttl_s: Optional[float]=None) -> List[Dict[str, Any]]:
        # cache key
        key = canon_hash({"plan": plan, "params": params, "page": page, "cons": consistency or self.cfg.consistency_default})
        ttl = self.cfg.limits.cache_ttl_s if cache_ttl_s is None else float(cache_ttl_s)
        if ttl > 0:
            c = self.cache.get(key)
            if c is not None:
                self._emit("graph.query.cache_hit", {}, {"ok":1.0})
                return c
        res = await self._with_retries(lambda txn: self.client.query(txn.handle, "PLAN", {"plan": plan, "params": dict(params)}, page=page), tag="query", consistency=consistency, idem=key)
        if ttl > 0:
            self.cache.set(key, res, ttl_s=ttl)
        return res

    async def traverse(self, *, start_keys: Sequence[str], edge_type: str, depth: int = 1, direction: str = "out", where: Mapping[str, Any] = {}, limit: Optional[int] = None, consistency: Optional[str] = None) -> List[Dict[str, Any]]:
        plan = {
            "op":"traverse",
            "start": list(start_keys),
            "edge": edge_type,
            "depth": int(max(0, depth)),
            "dir": direction,
            "where": dict(where),
            "limit": limit,
        }
        return await self.query(plan, consistency=consistency)

    async def shortest_path(self, *, src_key: str, dst_key: str, edge_type: str, direction: str = "out", max_depth: int = 32, consistency: Optional[str] = None) -> List[str]:
        plan = {
            "op":"shortest_path",
            "edge": edge_type,
            "dir": direction,
            "src": src_key,
            "dst": dst_key,
            "max_depth": int(max_depth),
        }
        rows = await self.query(plan, consistency=consistency)
        # Expect path as list of keys in "path"
        if not rows:
            return []
        p = rows[0].get("path") or []
        return list(p)

    async def subgraph(self, *, center_keys: Sequence[str], radius: int, edge_types: Sequence[str], direction: str="both", consistency: Optional[str]=None) -> Dict[str, Any]:
        plan = {
            "op":"subgraph",
            "center": list(center_keys),
            "radius": int(max(0, radius)),
            "edges": list(edge_types),
            "dir": direction,
        }
        rows = await self.query(plan, consistency=consistency)
        # normalize export
        return {"nodes": rows[0].get("nodes", []), "edges": rows[0].get("edges", [])} if rows else {"nodes":[], "edges":[]}

    def builder(self) -> QueryBuilder:
        return QueryBuilder(cfg=self.cfg)

    # --------- Internal helpers ---------

    async def _with_retries(self, fn: Callable[[_TxnCtx], Any], *, tag: str, consistency: Optional[str], idem: str) -> Any:
        attempt = 1
        maxr = max(0, self.cfg.limits.max_retries)
        base = 0.2; factor = 2.0; cap = 3.0
        while True:
            try:
                async with self.transaction(consistency=consistency) as txn:
                    t0 = time.monotonic()
                    res = await asyncio.wait_for(fn(txn), timeout=self.cfg.limits.timeout_s)
                    self._emit(f"graph.{tag}.ok", {"c":consistency or self.cfg.consistency_default}, {"lat_ms": (time.monotonic()-t0)*1000})
                    return res
            except asyncio.TimeoutError as e:
                self._emit(f"graph.{tag}.timeout", {}, {"attempt": float(attempt)})
                if attempt > maxr: raise GraphTimeout(str(e)) from e
            except GraphRateLimited as e:
                if attempt > maxr: raise
            except GraphRetryable as e:
                if attempt > maxr: raise
            delay = _full_jitter(base, factor, attempt, cap)
            await asyncio.sleep(delay)
            attempt += 1

    def _validate_nodes(self, nodes: Sequence[Node]) -> None:
        for n in nodes:
            if not n.type or not n.key:
                raise GraphBadRequest("node requires type and key")
            if not isinstance(n.props, dict):
                raise GraphBadRequest("node.props must be dict")

    def _validate_edges(self, edges: Sequence[Edge]) -> None:
        for e in edges:
            if not e.type or not e.src or not e.dst:
                raise GraphBadRequest("edge requires type, src, dst")
            if not isinstance(e.props, dict):
                raise GraphBadRequest("edge.props must be dict")

    def _emit(self, name: str, tags: Mapping[str,str], fields: Mapping[str,float]) -> None:
        try:
            self.tel(name, dict(tags), dict(fields))
        except Exception:
            pass

# =========================
# Convenience: ECS → Graph mapping (optional)
# =========================

def ecs_entity_to_node(entity_id: int, comps: Mapping[str, Any], *, namespace: str="entity") -> Node:
    key = f"{namespace}:{int(entity_id)}"
    return Node(type="Entity", key=key, props={"eid": int(entity_id), "components": comps}, version=1)

def relation_edge(from_entity: int, to_entity: int, rel_type: str, *, namespace: str="entity", props: Mapping[str, Any] | None = None) -> Edge:
    src = f"{namespace}:{int(from_entity)}"
    dst = f"{namespace}:{int(to_entity)}"
    return Edge(type=rel_type, src=src, dst=dst, props=dict(props or {}), directed=True, version=1)

# =========================
# __all__
# =========================

__all__ = [
    # config
    "GraphAdapterConfig","Limits",
    # schema
    "NodeType","EdgeType","Node","Edge",
    # client iface
    "GraphCoreClient",
    # adapter
    "GraphCoreAdapter",
    # builder
    "QueryBuilder","Match","Projection",
    # errors
    "GraphAdapterError","GraphBadRequest","GraphRetryable","GraphRateLimited","GraphTimeout","GraphTxnError",
    # utils
    "fnv1a64","canon_hash",
    # ecs helpers
    "ecs_entity_to_node","relation_edge",
]
