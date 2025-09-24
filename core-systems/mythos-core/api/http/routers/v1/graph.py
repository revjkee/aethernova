# -*- coding: utf-8 -*-
"""
Mythos Core — HTTP Graph API v1 router.
Промышленный слой REST над графовым ядром:
- CRUD: /nodes, /edges
- Batch mutate: /batch
- Query: /query/nodes, /query/edges
- Topology: /neighbors/{id}, /shortest-path
- Async jobs: /algos/start, /operations
- CDC events: /events (SSE)
- Import/Export: NDJSON streaming
- Идемпотентность: Idempotency-Key (POST/DELETE)
- Условные запросы: ETag / If-Match / If-None-Match
- Метаданные: X-Request-Id, X-Trace-Id, RateLimit*, Retry-After

Зависимость на FastAPI/Starlette и Pydantic. Бизнес-логика инжектируется через BaseGraphService.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, AsyncGenerator, Dict, Iterable, List, Literal, Optional, Tuple

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Body,
    Depends,
    Header,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import StreamingResponse, PlainTextResponse
from pydantic import BaseModel, Field, conint, constr

# --------------------------------------------------------------------------------------
# Утилиты
# --------------------------------------------------------------------------------------

def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

def compute_etag(doc: Any) -> str:
    """Детерминированный ETag по канонизированному JSON-представлению."""
    payload = _json_dumps(doc).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()

def now_ms() -> int:
    return int(time.time() * 1000)

def make_cursor(token: Optional[str], size: Optional[int]) -> Dict[str, Any]:
    return {"token": token or "", "size": size or 100}

# --------------------------------------------------------------------------------------
# Контракты API (модели)
# NB: Pydantic модели дублируют ключевые типы из proto/JSONSchema, но упрощены для HTTP.
# --------------------------------------------------------------------------------------

ULID = constr(regex=r"^[0-9A-HJKMNP-TV-Z]{26}$")
IdStr = constr(min_length=1, max_length=256)

class Value(BaseModel):
    s: Optional[str] = None
    i: Optional[int] = None
    d: Optional[float] = None
    b: Optional[bool] = None
    by: Optional[bytes] = None

class Properties(BaseModel):
    entries: Dict[str, Value] = Field(default_factory=dict, description="key->Value")

class Labels(BaseModel):
    entries: Dict[str, str] = Field(default_factory=dict)

class ResourceId(BaseModel):
    id: Optional[IdStr] = None
    # uuid как bytes опускаем в HTTP для простоты

class Audit(BaseModel):
    created_at: Optional[int] = Field(None, description="Unix ms")
    updated_at: Optional[int] = Field(None, description="Unix ms")
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    version: Optional[int] = 0
    etag: Optional[str] = None

class Node(BaseModel):
    resource: ResourceId
    kind: IdStr
    props: Properties = Properties()
    labels: Labels = Labels()
    audit: Audit = Audit()

class Edge(BaseModel):
    resource: ResourceId
    src: ResourceId
    dst: ResourceId
    type: IdStr
    props: Properties = Properties()
    labels: Labels = Labels()
    audit: Audit = Audit()
    directed: bool = True

class StatusModel(BaseModel):
    code: int = 1
    message: str = "OK"

class UpsertNodeRequest(BaseModel):
    node: Node
    allow_create: bool = True

class UpsertNodeResponse(BaseModel):
    node: Node
    status: StatusModel

class GetNodeResponse(BaseModel):
    node: Optional[Node] = None
    status: StatusModel

class DeleteNodeResponse(BaseModel):
    status: StatusModel

class UpsertEdgeRequest(BaseModel):
    edge: Edge
    allow_create: bool = True

class UpsertEdgeResponse(BaseModel):
    edge: Edge
    status: StatusModel

class GetEdgeResponse(BaseModel):
    edge: Optional[Edge] = None
    status: StatusModel

class DeleteEdgeResponse(BaseModel):
    status: StatusModel

class Filter(BaseModel):
    equals: Dict[str, Value] = Field(default_factory=dict)
    gte: Dict[str, Value] = Field(default_factory=dict)
    lte: Dict[str, Value] = Field(default_factory=dict)
    gt: Dict[str, Value] = Field(default_factory=dict)
    lt: Dict[str, Value] = Field(default_factory=dict)
    prefix: Dict[str, str] = Field(default_factory=dict)
    labels: Dict[str, str] = Field(default_factory=dict)
    kinds: List[str] = Field(default_factory=list)
    edge_types: List[str] = Field(default_factory=list)

class PageCursor(BaseModel):
    token: str = ""
    size: conint(ge=1, le=1000) = 100

class ReadOptions(BaseModel):
    consistency: Literal["EVENTUAL","STRONG"] = "EVENTUAL"
    include_props: bool = True
    include_labels: bool = True

class QueryNodesRequest(BaseModel):
    filter: Filter = Filter()
    page: PageCursor = PageCursor()
    read: ReadOptions = ReadOptions()

class QueryNodesResponse(BaseModel):
    nodes: List[Node] = Field(default_factory=list)
    next_page: PageCursor = PageCursor()
    status: StatusModel = StatusModel()

class QueryEdgesRequest(BaseModel):
    filter: Filter = Filter()
    page: PageCursor = PageCursor()
    read: ReadOptions = ReadOptions()

class QueryEdgesResponse(BaseModel):
    edges: List[Edge] = Field(default_factory=list)
    next_page: PageCursor = PageCursor()
    status: StatusModel = StatusModel()

class Neighbor(BaseModel):
    node: Node
    via: Edge

class GetNeighborsResponse(BaseModel):
    neighbors: List[Neighbor] = Field(default_factory=list)
    next_page: PageCursor = PageCursor()
    status: StatusModel = StatusModel()

class ShortestPathRequest(BaseModel):
    src: ResourceId
    dst: ResourceId
    edge_weight_property: Optional[str] = None
    edge_filter: Filter = Filter()
    max_hops: conint(ge=0, le=10000) = 0

class PathStep(BaseModel):
    node_id: ResourceId
    edge_id: Optional[ResourceId] = None

class ShortestPathResponse(BaseModel):
    steps: List[PathStep] = Field(default_factory=list)
    total_weight: float = 0.0
    status: StatusModel = StatusModel()

class BatchMutateRequest(BaseModel):
    upsert_nodes: List[UpsertNodeRequest] = Field(default_factory=list)
    upsert_edges: List[UpsertEdgeRequest] = Field(default_factory=list)
    delete_nodes: List[ResourceId] = Field(default_factory=list)
    delete_edges: List[ResourceId] = Field(default_factory=list)
    transactional: bool = False

class NodeResult(BaseModel):
    node: Optional[Node] = None
    status: StatusModel = StatusModel()

class EdgeResult(BaseModel):
    edge: Optional[Edge] = None
    status: StatusModel = StatusModel()

class BatchMutateResponse(BaseModel):
    node_results: List[NodeResult] = Field(default_factory=list)
    edge_results: List[EdgeResult] = Field(default_factory=list)
    status: StatusModel = StatusModel()

class StartAlgoJobRequest(BaseModel):
    algo: Literal["SHORTEST_PATH","PAGERANK","CONNECTED_COMPONENTS"]
    params: Dict[str, Value] = Field(default_factory=dict)
    scope: Filter = Filter()

class Operation(BaseModel):
    name: str
    done: bool
    error: Optional[Dict[str, Any]] = None
    response: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None

class StartAlgoJobResponse(BaseModel):
    op: Operation

# --------------------------------------------------------------------------------------
# Интерфейс графового сервиса (инжекция реализации)
# --------------------------------------------------------------------------------------

class BaseGraphService:
    """Контракт бизнес-логики. Реальная реализация предоставляется через Depends."""
    async def upsert_node(self, req: UpsertNodeRequest, idem_key: Optional[str]) -> UpsertNodeResponse: ...
    async def get_node(self, rid: str, read: ReadOptions) -> GetNodeResponse: ...
    async def delete_node(self, rid: str, etag: Optional[str], idem_key: Optional[str]) -> DeleteNodeResponse: ...
    async def upsert_edge(self, req: UpsertEdgeRequest, idem_key: Optional[str]) -> UpsertEdgeResponse: ...
    async def get_edge(self, rid: str, read: ReadOptions) -> GetEdgeResponse: ...
    async def delete_edge(self, rid: str, etag: Optional[str], idem_key: Optional[str]) -> DeleteEdgeResponse: ...
    async def batch_mutate(self, req: BatchMutateRequest, idem_key: Optional[str]) -> BatchMutateResponse: ...
    async def query_nodes(self, req: QueryNodesRequest) -> QueryNodesResponse: ...
    async def query_edges(self, req: QueryEdgesRequest) -> QueryEdgesResponse: ...
    async def neighbors(self, rid: str, direction: Literal["OUT","IN","ANY"], page: PageCursor, edge_filter: Filter, node_filter: Filter, read: ReadOptions) -> GetNeighborsResponse: ...
    async def shortest_path(self, req: ShortestPathRequest) -> ShortestPathResponse: ...
    async def start_algo(self, req: StartAlgoJobRequest) -> StartAlgoJobResponse: ...
    async def get_operation(self, name: str) -> Operation: ...
    async def list_operations(self, page: PageCursor) -> Tuple[List[Operation], PageCursor]: ...
    async def cancel_operation(self, name: str) -> StatusModel: ...
    async def stream_events(self, since_token: Optional[str]) -> AsyncGenerator[Dict[str, Any], None]: ...
    async def import_stream(self, items: Iterable[Dict[str, Any]]) -> Dict[str, int]: ...
    async def export_stream(self, filt: Filter, chunk_size: int) -> AsyncGenerator[Dict[str, Any], None]: ...

# Временная mock-реализация для «сухого» запуска API без ядра.
class _MockGraphService(BaseGraphService):
    async def upsert_node(self, req, idem_key):  # type: ignore[override]
        n = req.node
        n.audit.updated_at = now_ms()
        n.audit.etag = compute_etag(n.dict())
        return UpsertNodeResponse(node=n, status=StatusModel())
    async def get_node(self, rid, read):  # type: ignore[override]
        return GetNodeResponse(node=None, status=StatusModel(code=5, message="NOT_FOUND"))
    async def delete_node(self, rid, etag, idem_key):  # type: ignore[override]
        return DeleteNodeResponse(status=StatusModel())
    async def upsert_edge(self, req, idem_key):  # type: ignore[override]
        e = req.edge
        e.audit.updated_at = now_ms()
        e.audit.etag = compute_etag(e.dict())
        return UpsertEdgeResponse(edge=e, status=StatusModel())
    async def get_edge(self, rid, read):  # type: ignore[override]
        return GetEdgeResponse(edge=None, status=StatusModel(code=5, message="NOT_FOUND"))
    async def delete_edge(self, rid, etag, idem_key):  # type: ignore[override]
        return DeleteEdgeResponse(status=StatusModel())
    async def batch_mutate(self, req, idem_key):  # type: ignore[override]
        return BatchMutateResponse()
    async def query_nodes(self, req):  # type: ignore[override]
        return QueryNodesResponse()
    async def query_edges(self, req):  # type: ignore[override]
        return QueryEdgesResponse()
    async def neighbors(self, rid, direction, page, edge_filter, node_filter, read):  # type: ignore[override]
        return GetNeighborsResponse()
    async def shortest_path(self, req):  # type: ignore[override]
        return ShortestPathResponse()
    async def start_algo(self, req):  # type: ignore[override]
        return StartAlgoJobResponse(op=Operation(name="op/mock", done=False, metadata={"started_at": now_ms()}))
    async def get_operation(self, name):  # type: ignore[override]
        return Operation(name=name, done=True, response={"ok": True})
    async def list_operations(self, page):  # type: ignore[override]
        return [], PageCursor()
    async def cancel_operation(self, name):  # type: ignore[override]
        return StatusModel()
    async def stream_events(self, since_token):  # type: ignore[override]
        # Пример: одно событие и завершение
        yield {"kind": "HEARTBEAT", "ts": now_ms()}
    async def import_stream(self, items):  # type: ignore[override]
        cnt = 0
        for _ in items:
            cnt += 1
        return {"items": cnt}
    async def export_stream(self, filt, chunk_size):  # type: ignore[override]
        # Пустой поток
        if False:
            yield {}  # pragma: no cover

# DI-хук. В проде замените на реальную реализацию.
async def get_graph_service() -> BaseGraphService:
    return _MockGraphService()

# --------------------------------------------------------------------------------------
# Роутер
# --------------------------------------------------------------------------------------

router = APIRouter(prefix="/v1/graph", tags=["graph"])

# --------------------- Общий обработчик ошибок/заголовков -----------------------------

def _set_common_headers(resp: Response, request_id: Optional[str]) -> None:
    if request_id:
        resp.headers["X-Request-Id"] = request_id
    resp.headers.setdefault("Cache-Control", "no-store")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")

# ----------------------------------- Nodes --------------------------------------------

@router.post(
    "/nodes",
    response_model=UpsertNodeResponse,
    status_code=status.HTTP_201_CREATED,
    responses={409: {"description": "ETag/Version conflict"}, 429: {"description": "Rate limited"}},
)
async def upsert_node(
    req: UpsertNodeRequest,
    response: Response,
    graph: BaseGraphService = Depends(get_graph_service),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
):
    res = await graph.upsert_node(req, idempotency_key)
    etag = res.node.audit.etag or compute_etag(res.node.dict())
    response.headers["ETag"] = etag
    _set_common_headers(response, request_id)
    return res


@router.get(
    "/nodes/{node_id}",
    response_model=GetNodeResponse,
    responses={304: {"description": "Not Modified"}, 404: {"description": "Not Found"}},
)
async def get_node(
    node_id: IdStr = Path(..., description="Resource id"),
    include_props: bool = Query(True),
    include_labels: bool = Query(True),
    consistency: Literal["EVENTUAL","STRONG"] = Query("EVENTUAL"),
    if_none_match: Optional[str] = Header(default=None, alias="If-None-Match"),
    response: Response = None,  # type: ignore[assignment]
    graph: BaseGraphService = Depends(get_graph_service),
    request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
):
    res = await graph.get_node(node_id, ReadOptions(consistency=consistency, include_props=include_props, include_labels=include_labels))
    if not res.node:
        raise HTTPException(status_code=404, detail="Node not found")
    etag = res.node.audit.etag or compute_etag(res.node.dict())
    if if_none_match and if_none_match == etag:
        _set_common_headers(response, request_id)
        return Response(status_code=304)
    response.headers["ETag"] = etag
    _set_common_headers(response, request_id)
    return res


@router.delete(
    "/nodes/{node_id}",
    response_model=DeleteNodeResponse,
    status_code=status.HTTP_200_OK,
    responses={412: {"description": "Precondition Failed"}},
)
async def delete_node(
    node_id: IdStr,
    graph: BaseGraphService = Depends(get_graph_service),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    response: Response = None,  # type: ignore[assignment]
    request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
):
    res = await graph.delete_node(node_id, if_match, idempotency_key)
    _set_common_headers(response, request_id)
    return res

# ----------------------------------- Edges --------------------------------------------

@router.post("/edges", response_model=UpsertEdgeResponse, status_code=201)
async def upsert_edge(
    req: UpsertEdgeRequest,
    response: Response,
    graph: BaseGraphService = Depends(get_graph_service),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
):
    res = await graph.upsert_edge(req, idempotency_key)
    etag = res.edge.audit.etag or compute_etag(res.edge.dict())
    response.headers["ETag"] = etag
    _set_common_headers(response, request_id)
    return res


@router.get("/edges/{edge_id}", response_model=GetEdgeResponse)
async def get_edge(
    edge_id: IdStr,
    include_props: bool = Query(True),
    include_labels: bool = Query(True),
    consistency: Literal["EVENTUAL","STRONG"] = Query("EVENTUAL"),
    if_none_match: Optional[str] = Header(default=None, alias="If-None-Match"),
    response: Response = None,  # type: ignore[assignment]
    graph: BaseGraphService = Depends(get_graph_service),
    request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
):
    res = await graph.get_edge(edge_id, ReadOptions(consistency=consistency, include_props=include_props, include_labels=include_labels))
    if not res.edge:
        raise HTTPException(status_code=404, detail="Edge not found")
    etag = res.edge.audit.etag or compute_etag(res.edge.dict())
    if if_none_match and if_none_match == etag:
        _set_common_headers(response, request_id)
        return Response(status_code=304)
    response.headers["ETag"] = etag
    _set_common_headers(response, request_id)
    return res


@router.delete("/edges/{edge_id}", response_model=DeleteEdgeResponse)
async def delete_edge(
    edge_id: IdStr,
    graph: BaseGraphService = Depends(get_graph_service),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    response: Response = None,  # type: ignore[assignment]
    request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
):
    res = await graph.delete_edge(edge_id, if_match, idempotency_key)
    _set_common_headers(response, request_id)
    return res

# -------------------------------- Batch / Query ---------------------------------------

@router.post("/batch", response_model=BatchMutateResponse)
async def batch_mutate(
    req: BatchMutateRequest,
    graph: BaseGraphService = Depends(get_graph_service),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    response: Response = None,  # type: ignore[assignment]
    request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
):
    res = await graph.batch_mutate(req, idempotency_key)
    _set_common_headers(response, request_id)
    return res

@router.post("/query/nodes", response_model=QueryNodesResponse)
async def query_nodes(
    req: QueryNodesRequest,
    graph: BaseGraphService = Depends(get_graph_service),
    response: Response = None,  # type: ignore[assignment]
    request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
):
    res = await graph.query_nodes(req)
    _set_common_headers(response, request_id)
    return res

@router.post("/query/edges", response_model=QueryEdgesResponse)
async def query_edges(
    req: QueryEdgesRequest,
    graph: BaseGraphService = Depends(get_graph_service),
    response: Response = None,  # type: ignore[assignment]
    request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
):
    res = await graph.query_edges(req)
    _set_common_headers(response, request_id)
    return res

# -------------------------------- Neighbors / Path ------------------------------------

@router.get("/neighbors/{node_id}", response_model=GetNeighborsResponse)
async def get_neighbors(
    node_id: IdStr,
    direction: Literal["OUT", "IN", "ANY"] = Query("OUT"),
    page_token: Optional[str] = Query(None),
    page_size: Optional[int] = Query(100, ge=1, le=1000),
    graph: BaseGraphService = Depends(get_graph_service),
    response: Response = None,  # type: ignore[assignment]
    request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
):
    res = await graph.neighbors(
        rid=node_id,
        direction=direction,
        page=PageCursor(token=page_token or "", size=page_size or 100),
        edge_filter=Filter(),
        node_filter=Filter(),
        read=ReadOptions(),
    )
    _set_common_headers(response, request_id)
    return res

@router.post("/shortest-path", response_model=ShortestPathResponse)
async def shortest_path(
    req: ShortestPathRequest,
    graph: BaseGraphService = Depends(get_graph_service),
    response: Response = None,  # type: ignore[assignment]
    request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
):
    res = await graph.shortest_path(req)
    _set_common_headers(response, request_id)
    return res

# -------------------------------- Async operations ------------------------------------

@router.post("/algos/start", response_model=StartAlgoJobResponse, status_code=202)
async def start_algo(
    req: StartAlgoJobRequest,
    graph: BaseGraphService = Depends(get_graph_service),
    response: Response = None,  # type: ignore[assignment]
    request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
):
    res = await graph.start_algo(req)
    _set_common_headers(response, request_id)
    response.headers["Location"] = f"/v1/graph/operations/{res.op.name}"
    return res

@router.get("/operations/{name}", response_model=Operation)
async def get_operation(
    name: str,
    graph: BaseGraphService = Depends(get_graph_service),
    response: Response = None,  # type: ignore[assignment]
    request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
):
    op = await graph.get_operation(name)
    _set_common_headers(response, request_id)
    return op

@router.get("/operations", response_model=List[Operation])
async def list_operations(
    page_token: Optional[str] = Query(None),
    page_size: Optional[int] = Query(100, ge=1, le=1000),
    graph: BaseGraphService = Depends(get_graph_service),
    response: Response = None,  # type: ignore[assignment]
    request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
):
    items, next_page = await graph.list_operations(PageCursor(token=page_token or "", size=page_size or 100))
    if next_page and next_page.token:
        response.headers["X-Next-Page-Token"] = next_page.token
    _set_common_headers(response, request_id)
    return items

@router.delete("/operations/{name}", response_model=StatusModel)
async def cancel_operation(
    name: str,
    graph: BaseGraphService = Depends(get_graph_service),
    response: Response = None,  # type: ignore[assignment]
    request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
):
    st = await graph.cancel_operation(name)
    _set_common_headers(response, request_id)
    return st

# ----------------------------------- Events (SSE) -------------------------------------

async def _sse_iter(gen: AsyncGenerator[Dict[str, Any], None]) -> AsyncGenerator[bytes, None]:
    try:
        async for evt in gen:
            # event: <type> (опционально) — можно добавить при необходимости
            data = _json_dumps(evt)
            yield f"data: {data}\n\n".encode("utf-8")
            await asyncio.sleep(0)  # кооперативность
    finally:
        # Грейсфул завершение
        yield b": bye\n\n"

@router.get("/events")
async def stream_events(
    since: Optional[str] = Query(None, description="Курсор/токен для продолжения"),
    graph: BaseGraphService = Depends(get_graph_service),
):
    gen = graph.stream_events(since)
    return StreamingResponse(_sse_iter(gen), media_type="text/event-stream")

# -------------------------------- Import / Export (NDJSON) -----------------------------

@router.post("/import")
async def import_graph(
    request: Request,
    graph: BaseGraphService = Depends(get_graph_service),
):
    async def _iter_items() -> AsyncGenerator[Dict[str, Any], None]:
        """
        Ожидается NDJSON поток: по строке на документ.
        Документы могут быть Node/Edge/BatchChunk, сервис решает что это.
        """
        async for line in request.stream():
            if not line:
                continue
            obj = json.loads(line)
            yield obj

    summary = await graph.import_stream(_iter_items())
    return summary

@router.post("/export")
async def export_graph(
    filt: Filter = Body(default=Filter()),
    chunk_size: int = Query(1000, ge=1, le=10000),
    graph: BaseGraphService = Depends(get_graph_service),
):
    async def _ndjson() -> AsyncGenerator[bytes, None]:
        async for chunk in graph.export_stream(filt, chunk_size):
            yield (_json_dumps(chunk) + "\n").encode("utf-8")

    headers = {
        "Content-Disposition": 'attachment; filename="graph.ndjson"',
        "Content-Type": "application/x-ndjson; charset=utf-8",
    }
    return StreamingResponse(_ndjson(), headers=headers)

# --------------------------------- Liveness (optional) --------------------------------

@router.get("/__internal__/ready")
async def ready() -> PlainTextResponse:
    return PlainTextResponse("ok", status_code=200)
