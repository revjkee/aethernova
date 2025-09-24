# -*- coding: utf-8 -*-
"""
DataFabric HTTP API — Lineage router (FastAPI/Starlette).

Endpoints (prefix=/v1/lineage):
  POST   /nodes                    -> upsert node (idempotent by natural key)
  GET    /nodes/{node_id}          -> fetch node
  POST   /edges                    -> upsert edge (idempotent by fingerprint)
  DELETE /edges/{edge_id}          -> delete edge (soft)
  GET    /graph/upstream           -> traverse upstream (BFS)
  GET    /graph/downstream         -> traverse downstream (BFS)
  POST   /impact                   -> impact analysis from a set of nodes
  GET    /search                   -> search nodes (name/labels), paginated

Design:
  - Strong Pydantic models; enumerations for node/edge types.
  - Tenancy-awareness (tenant_id) baked into node/edge; request can filter by tenant.
  - Idempotent upsert via deterministic fingerprints.
  - Traversals bounded by depth/node/edge limits + type/time filters => predictable cost.
  - Stable GraphDTO (nodes, edges, stats). ETag and no-store headers.
  - Storage abstraction (LineageStore) + in-memory fallback.
"""

from __future__ import annotations

import base64
import hashlib
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Literal, Optional, Set, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field, conint, constr, validator

# ------------------------------------------------------------------------------
# Models
# ------------------------------------------------------------------------------

NodeType = Literal[
    "DATASET", "TABLE", "COLUMN", "TOPIC", "JOB", "PIPELINE", "MODEL", "DASHBOARD", "FILE"
]

EdgeType = Literal[
    "PRODUCES",   # JOB -> DATASET
    "CONSUMES",   # JOB <- DATASET (DATASET -> JOB)
    "TRANSFORMS", # DATASET -> DATASET
    "DERIVES",    # COLUMN -> COLUMN
    "JOINS",      # DATASET -> DATASET (join)
    "COPIES"      # DATASET -> DATASET (copy/move)
]

class Node(BaseModel):
    node_id: constr(strip_whitespace=True, min_length=1) = Field(..., description="Stable ID (UUID/ULID or external key)")
    tenant_id: constr(strip_whitespace=True, min_length=1)
    type: NodeType
    name: constr(strip_whitespace=True, min_length=1)
    qualified_name: Optional[str] = Field(None, description="e.g. s3://bucket/prefix or db.schema.table")
    labels: Dict[str, str] = Field(default_factory=dict)
    created_at: Optional[int] = Field(None, description="epoch micros")
    updated_at: Optional[int] = Field(None, description="epoch micros")
    active: bool = True

    @validator("labels")
    def _labels_len(cls, v: Dict[str, str]) -> Dict[str, str]:
        for k, val in v.items():
            if len(k) > 64 or len(val) > 256:
                raise ValueError("label key/value too long")
        return v

class Edge(BaseModel):
    edge_id: Optional[str] = Field(None, description="If omitted, computed as fingerprint")
    tenant_id: constr(strip_whitespace=True, min_length=1)
    type: EdgeType
    from_id: constr(strip_whitespace=True, min_length=1)
    to_id: constr(strip_whitespace=True, min_length=1)
    run_id: Optional[str] = Field(None, description="Execution/run that emitted this edge")
    trace_id: Optional[str] = None
    occurred_at: Optional[int] = Field(None, description="epoch micros when relation occurred")
    version: Optional[str] = Field(None, description="Logical version of producer artifact")
    confidence: Optional[float] = Field(1.0, ge=0.0, le=1.0)
    labels: Dict[str, str] = Field(default_factory=dict)
    active: bool = True

    @validator("labels")
    def _labels_len(cls, v: Dict[str, str]) -> Dict[str, str]:
        for k, val in v.items():
            if len(k) > 64 or len(val) > 256:
                raise ValueError("label key/value too long")
        return v

class UpsertNodeRequest(BaseModel):
    node: Node

class UpsertNodeResponse(BaseModel):
    node: Node
    created: bool

class UpsertEdgeRequest(BaseModel):
    edge: Edge
    idempotency_key: Optional[str] = None

class UpsertEdgeResponse(BaseModel):
    edge: Edge
    created: bool
    fingerprint: str

class DeleteEdgeResponse(BaseModel):
    success: bool

class GraphNode(BaseModel):
    node_id: str
    type: NodeType
    name: str
    qualified_name: Optional[str] = None
    labels: Dict[str, str] = Field(default_factory=dict)

class GraphEdge(BaseModel):
    edge_id: str
    type: EdgeType
    from_id: str
    to_id: str
    run_id: Optional[str] = None
    occurred_at: Optional[int] = None
    confidence: Optional[float] = 1.0

class GraphDTO(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    start: List[str] = Field(..., description="Start node ids")
    direction: Literal["UPSTREAM", "DOWNSTREAM"]
    depth: int
    truncated: bool
    stats: Dict[str, Any] = Field(default_factory=dict)

class ImpactResponse(BaseModel):
    by_distance: Dict[str, List[str]]
    total_unique: int
    truncated: bool

class SearchResponse(BaseModel):
    items: List[GraphNode]
    next_page_token: Optional[str] = None

# ------------------------------------------------------------------------------
# Storage abstraction (DI)
# ------------------------------------------------------------------------------

class LineageStore:
    async def upsert_node(self, node: Node) -> Tuple[Node, bool]:
        raise NotImplementedError

    async def get_node(self, tenant_id: str, node_id: str) -> Optional[Node]:
        raise NotImplementedError

    async def upsert_edge(self, edge: Edge, fingerprint: str) -> Tuple[Edge, bool]:
        raise NotImplementedError

    async def delete_edge(self, tenant_id: str, edge_id: str) -> bool:
        raise NotImplementedError

    async def neighbors(
        self,
        tenant_id: str,
        node_id: str,
        direction: Literal["UPSTREAM", "DOWNSTREAM"],
        *,
        since_micros: Optional[int] = None,
        until_micros: Optional[int] = None,
        edge_types: Optional[Set[EdgeType]] = None,
    ) -> List[Edge]:
        raise NotImplementedError

    async def bulk_get_nodes(self, tenant_id: str, ids: Iterable[str]) -> Dict[str, Node]:
        raise NotImplementedError

    async def search_nodes(
        self, tenant_id: Optional[str], q: Optional[str], page_size: int, page_token: Optional[str]
    ) -> Tuple[List[Node], Optional[str]]:
        raise NotImplementedError

# In-memory fallback implementation (thread-safe enough for single process)

@dataclass
class _MemEdge:
    edge: Edge
    deleted: bool = False

class InMemoryLineageStore(LineageStore):
    def __init__(self) -> None:
        self.nodes: Dict[Tuple[str, str], Node] = {}
        self.edges: Dict[Tuple[str, str], _MemEdge] = {}
        self.by_from: Dict[Tuple[str, str], Set[str]] = {}
        self.by_to: Dict[Tuple[str, str], Set[str]] = {}

    async def upsert_node(self, node: Node) -> Tuple[Node, bool]:
        key = (node.tenant_id, node.node_id)
        created = key not in self.nodes
        now_us = int(time.time() * 1_000_000)
        if created:
            node.created_at = node.created_at or now_us
        node.updated_at = now_us
        self.nodes[key] = node
        return node, created

    async def get_node(self, tenant_id: str, node_id: str) -> Optional[Node]:
        return self.nodes.get((tenant_id, node_id))

    async def upsert_edge(self, edge: Edge, fingerprint: str) -> Tuple[Edge, bool]:
        edge_id = edge.edge_id or fingerprint
        edge.edge_id = edge_id
        key = (edge.tenant_id, edge_id)
        created = key not in self.edges
        self.edges[key] = _MemEdge(edge=edge, deleted=False)
        self.by_from.setdefault((edge.tenant_id, edge.from_id), set()).add(edge_id)
        self.by_to.setdefault((edge.tenant_id, edge.to_id), set()).add(edge_id)
        return edge, created

    async def delete_edge(self, tenant_id: str, edge_id: str) -> bool:
        key = (tenant_id, edge_id)
        mem = self.edges.get(key)
        if not mem or mem.deleted:
            return False
        mem.deleted = True
        # do not physically unlink from indices to keep complexity low
        return True

    async def neighbors(
        self,
        tenant_id: str,
        node_id: str,
        direction: Literal["UPSTREAM", "DOWNSTREAM"],
        *,
        since_micros: Optional[int] = None,
        until_micros: Optional[int] = None,
        edge_types: Optional[Set[EdgeType]] = None,
    ) -> List[Edge]:
        edge_ids = (self.by_to if direction == "UPSTREAM" else self.by_from).get((tenant_id, node_id), set())
        res: List[Edge] = []
        for eid in edge_ids:
            mem = self.edges.get((tenant_id, eid))
            if not mem or mem.deleted or not mem.edge.active:
                continue
            e = mem.edge
            if edge_types and e.type not in edge_types:
                continue
            if since_micros and (e.occurred_at or 0) < since_micros:
                continue
            if until_micros and (e.occurred_at or 0) > until_micros:
                continue
            res.append(e)
        return res

    async def bulk_get_nodes(self, tenant_id: str, ids: Iterable[str]) -> Dict[str, Node]:
        return {nid: self.nodes[(tenant_id, nid)] for nid in ids if (tenant_id, nid) in self.nodes}

    async def search_nodes(
        self, tenant_id: Optional[str], q: Optional[str], page_size: int, page_token: Optional[str]
    ) -> Tuple[List[Node], Optional[str]]:
        # naive scanning; replace with DB-backed search in production
        start = int(base64.urlsafe_b64decode(page_token + "==").decode("utf-8")) if page_token else 0
        items = []
        universe = [n for (t, _), n in self.nodes.items() if (tenant_id is None or t == tenant_id)]
        qnorm = (q or "").strip().lower()
        for n in universe:
            if qnorm and (qnorm not in n.name.lower()) and (qnorm not in (n.qualified_name or "").lower()):
                continue
            items.append(n)
        items.sort(key=lambda x: (x.type, x.name))
        next_token = None
        if start + page_size < len(items):
            next_token = base64.urlsafe_b64encode(str(start + page_size).encode("utf-8")).decode("utf-8").rstrip("=")
        return items[start : start + page_size], next_token

# ------------------------------------------------------------------------------
# DI wiring
# ------------------------------------------------------------------------------

_STORE_SINGLETON: LineageStore = InMemoryLineageStore()

def get_store() -> LineageStore:
    # Replace with a provider that returns a DB-backed store (Neo4j/PG) if configured.
    return _STORE_SINGLETON

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

def _no_store_headers(resp: Response) -> None:
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, proxy-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    resp.headers["Content-Type"] = "application/json; charset=utf-8"

def _edge_fingerprint(edge: Edge) -> str:
    # Deterministic, stable fingerprint for idempotency
    src = "|".join(
        [
            edge.tenant_id,
            edge.type,
            edge.from_id,
            edge.to_id,
            str(edge.run_id or ""),
            str(edge.version or ""),
            str(edge.trace_id or ""),
        ]
    )
    return hashlib.sha256(src.encode("utf-8")).hexdigest()

def _etag_graph(nodes: List[GraphNode], edges: List[GraphEdge]) -> str:
    h = hashlib.sha256()
    for n in sorted(nodes, key=lambda x: x.node_id):
        h.update(n.node_id.encode("utf-8")); h.update((n.name or "").encode("utf-8"))
    for e in sorted(edges, key=lambda x: x.edge_id):
        h.update(e.edge_id.encode("utf-8"))
    return '"' + h.hexdigest() + '"'

async def _bfs_traverse(
    store: LineageStore,
    tenant_id: str,
    start_ids: List[str],
    direction: Literal["UPSTREAM", "DOWNSTREAM"],
    *,
    depth: int,
    max_nodes: int,
    max_edges: int,
    edge_types: Optional[Set[EdgeType]],
    since_micros: Optional[int],
    until_micros: Optional[int],
) -> Tuple[List[GraphNode], List[GraphEdge], bool]:
    """Bounded BFS with type/time filters; returns nodes, edges, truncated."""
    visited_nodes: Set[str] = set(start_ids)
    out_nodes: Dict[str, GraphNode] = {}
    out_edges: Dict[str, GraphEdge] = {}
    frontier: List[Tuple[str, int]] = [(sid, 0) for sid in start_ids]
    truncated = False

    # Prime with start nodes
    nodes_map = await store.bulk_get_nodes(tenant_id, start_ids)
    for n in nodes_map.values():
        out_nodes[n.node_id] = GraphNode(
            node_id=n.node_id,
            type=n.type,
            name=n.name,
            qualified_name=n.qualified_name,
            labels=n.labels,
        )

    while frontier:
        node_id, dist = frontier.pop(0)
        if dist >= depth:
            continue
        neighbors = await store.neighbors(
            tenant_id,
            node_id,
            direction,
            since_micros=since_micros,
            until_micros=until_micros,
            edge_types=edge_types,
        )
        for e in neighbors:
            eid = e.edge_id or _edge_fingerprint(e)
            if eid not in out_edges:
                out_edges[eid] = GraphEdge(
                    edge_id=eid,
                    type=e.type,
                    from_id=e.from_id,
                    to_id=e.to_id,
                    run_id=e.run_id,
                    occurred_at=e.occurred_at,
                    confidence=e.confidence,
                )
            next_id = e.from_id if direction == "UPSTREAM" else e.to_id
            if next_id not in visited_nodes:
                visited_nodes.add(next_id)
                # fetch node
                nm = await store.bulk_get_nodes(tenant_id, [next_id])
                n = nm.get(next_id)
                if n:
                    out_nodes[next_id] = GraphNode(
                        node_id=n.node_id, type=n.type, name=n.name, qualified_name=n.qualified_name, labels=n.labels
                    )
                frontier.append((next_id, dist + 1))
            if len(out_nodes) >= max_nodes or len(out_edges) >= max_edges:
                truncated = True
                frontier.clear()
                break

    return list(out_nodes.values()), list(out_edges.values()), truncated

# ------------------------------------------------------------------------------
# Router
# ------------------------------------------------------------------------------

router = APIRouter(prefix="/v1/lineage", tags=["lineage"])

# --- Nodes --------------------------------------------------------------------

@router.post("/nodes", response_model=UpsertNodeResponse, status_code=200, summary="Upsert node")
async def upsert_node(req: UpsertNodeRequest, response: Response, store: LineageStore = Depends(get_store)) -> UpsertNodeResponse:
    node, created = await store.upsert_node(req.node)
    _no_store_headers(response)
    return UpsertNodeResponse(node=node, created=created)

@router.get("/nodes/{node_id}", response_model=Node, summary="Get node by id")
async def get_node(node_id: str, tenant_id: str = Query(...), response: Response = None, store: LineageStore = Depends(get_store)) -> Node:
    node = await store.get_node(tenant_id, node_id)
    if not node:
        raise HTTPException(status_code=404, detail="node not found")
    if response:
        _no_store_headers(response)
    return node

# --- Edges --------------------------------------------------------------------

@router.post("/edges", response_model=UpsertEdgeResponse, status_code=200, summary="Upsert edge")
async def upsert_edge(req: UpsertEdgeRequest, response: Response, store: LineageStore = Depends(get_store)) -> UpsertEdgeResponse:
    edge = req.edge
    fp = _edge_fingerprint(edge if not req.idempotency_key else Edge(**{**edge.dict(), "trace_id": req.idempotency_key}))
    edge, created = await store.upsert_edge(edge, fp)
    _no_store_headers(response)
    return UpsertEdgeResponse(edge=edge, created=created, fingerprint=fp)

@router.delete("/edges/{edge_id}", response_model=DeleteEdgeResponse, summary="Delete (soft) edge by id")
async def delete_edge(edge_id: str, tenant_id: str = Query(...), response: Response = None, store: LineageStore = Depends(get_store)) -> DeleteEdgeResponse:
    ok = await store.delete_edge(tenant_id, edge_id)
    if not ok:
        raise HTTPException(status_code=404, detail="edge not found")
    if response:
        _no_store_headers(response)
    return DeleteEdgeResponse(success=True)

# --- Traversal ----------------------------------------------------------------

@router.get("/graph/upstream", response_model=GraphDTO, summary="Traverse upstream (inputs)")
async def graph_upstream(
    response: Response,
    tenant_id: str = Query(...),
    node_id: List[str] = Query(..., alias="node_id"),
    depth: conint(ge=0, le=16) = 3,
    max_nodes: conint(ge=1, le=20000) = 2000,
    max_edges: conint(ge=1, le=40000) = 4000,
    edge_type: Optional[List[EdgeType]] = Query(None),
    since_micros: Optional[int] = Query(None),
    until_micros: Optional[int] = Query(None),
    store: LineageStore = Depends(get_store),
) -> GraphDTO:
    nodes, edges, truncated = await _bfs_traverse(
        store,
        tenant_id,
        node_id,
        "UPSTREAM",
        depth=depth,
        max_nodes=max_nodes,
        max_edges=max_edges,
        edge_types=set(edge_type) if edge_type else None,
        since_micros=since_micros,
        until_micros=until_micros,
    )
    dto = GraphDTO(
        nodes=nodes,
        edges=edges,
        start=node_id,
        direction="UPSTREAM",
        depth=depth,
        truncated=truncated,
        stats={"nodes": len(nodes), "edges": len(edges)},
    )
    _no_store_headers(response)
    response.headers["ETag"] = _etag_graph(dto.nodes, dto.edges)
    return dto

@router.get("/graph/downstream", response_model=GraphDTO, summary="Traverse downstream (outputs)")
async def graph_downstream(
    response: Response,
    tenant_id: str = Query(...),
    node_id: List[str] = Query(..., alias="node_id"),
    depth: conint(ge=0, le=16) = 3,
    max_nodes: conint(ge=1, le=20000) = 2000,
    max_edges: conint(ge=1, le=40000) = 4000,
    edge_type: Optional[List[EdgeType]] = Query(None),
    since_micros: Optional[int] = Query(None),
    until_micros: Optional[int] = Query(None),
    store: LineageStore = Depends(get_store),
) -> GraphDTO:
    nodes, edges, truncated = await _bfs_traverse(
        store,
        tenant_id,
        node_id,
        "DOWNSTREAM",
        depth=depth,
        max_nodes=max_nodes,
        max_edges=max_edges,
        edge_types=set(edge_type) if edge_type else None,
        since_micros=since_micros,
        until_micros=until_micros,
    )
    dto = GraphDTO(
        nodes=nodes,
        edges=edges,
        start=node_id,
        direction="DOWNSTREAM",
        depth=depth,
        truncated=truncated,
        stats={"nodes": len(nodes), "edges": len(edges)},
    )
    _no_store_headers(response)
    response.headers["ETag"] = _etag_graph(dto.nodes, dto.edges)
    return dto

# --- Impact analysis -----------------------------------------------------------

class ImpactRequest(BaseModel):
    tenant_id: str
    start_nodes: List[str]
    direction: Literal["DOWNSTREAM", "UPSTREAM"] = "DOWNSTREAM"
    depth: conint(ge=0, le=16) = 5
    max_nodes: conint(ge=1, le=20000) = 5000
    max_edges: conint(ge=1, le=40000) = 20000
    edge_type: Optional[List[EdgeType]] = None
    since_micros: Optional[int] = None
    until_micros: Optional[int] = None

@router.post("/impact", response_model=ImpactResponse, summary="Impact analysis from a set of nodes")
async def impact(req: ImpactRequest, response: Response, store: LineageStore = Depends(get_store)) -> ImpactResponse:
    # Run BFS and then bucketize by distance
    nodes, edges, truncated = await _bfs_traverse(
        store,
        req.tenant_id,
        req.start_nodes,
        req.direction,
        depth=req.depth,
        max_nodes=req.max_nodes,
        max_edges=req.max_edges,
        edge_types=set(req.edge_type) if req.edge_type else None,
        since_micros=req.since_micros,
        until_micros=req.until_micros,
    )
    # simple distance bucketing: re-run single-source BFS distances cheaply
    # (approximate: distance unknown for all, we compute a union of distances)
    by_dist: Dict[str, Set[str]] = {}
    # mark start at 0
    by_dist["0"] = set(req.start_nodes)
    # neighbors of DTO edges to estimate distances
    adj: Dict[str, Set[str]] = {}
    rev: Dict[str, Set[str]] = {}
    for e in edges:
        adj.setdefault(e.from_id, set()).add(e.to_id)
        rev.setdefault(e.to_id, set()).add(e.from_id)
    # BFS from starts in chosen direction on the reduced graph
    from collections import deque
    dist: Dict[str, int] = {sid: 0 for sid in req.start_nodes}
    dq = deque(req.start_nodes)
    while dq:
        u = dq.popleft()
        neigh = (rev.get(u, set()) if req.direction == "UPSTREAM" else adj.get(u, set()))
        for v in neigh:
            if v not in dist:
                dist[v] = dist[u] + 1
                dq.append(v)
    for nid, d in dist.items():
        by_dist.setdefault(str(d), set()).add(nid)
    by_distance = {k: sorted(list(v)) for k, v in sorted(by_dist.items(), key=lambda kv: int(kv[0]))}
    _no_store_headers(response)
    return ImpactResponse(by_distance=by_distance, total_unique=len(dist), truncated=truncated)

# --- Search --------------------------------------------------------------------

@router.get("/search", response_model=SearchResponse, summary="Search nodes")
async def search(
    response: Response,
    tenant_id: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    page_size: conint(ge=1, le=500) = 50,
    page_token: Optional[str] = Query(None),
    store: LineageStore = Depends(get_store),
) -> SearchResponse:
    items, next_token = await store.search_nodes(tenant_id, q, page_size, page_token)
    gn = [
        GraphNode(node_id=n.node_id, type=n.type, name=n.name, qualified_name=n.qualified_name, labels=n.labels) for n in items
    ]
    _no_store_headers(response)
    return SearchResponse(items=gn, next_page_token=next_token)
