# datafabric-core/api/graphql/server.py
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import strawberry
from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from pydantic import BaseSettings, Field, AnyHttpUrl, validator
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, PlainTextResponse, HTMLResponse
from starlette.routing import Mount
from strawberry.schema import BaseSchema
from strawberry.types import ExecutionResult
from graphql import parse, DocumentNode, OperationDefinitionNode, visit

# -----------------------------
# Configuration
# -----------------------------

class Settings(BaseSettings):
    APP_NAME: str = "datafabric-graphql"
    HOST: str = "0.0.0.0"
    PORT: int = 8080
    DEBUG: bool = False

    # CORS
    ALLOW_ORIGINS: list[AnyHttpUrl | str] = Field(default_factory=lambda: ["*"])
    ALLOW_METHODS: list[str] = Field(default_factory=lambda: ["GET", "POST", "OPTIONS"])
    ALLOW_HEADERS: list[str] = Field(default_factory=lambda: ["*"])

    # Rate limit (requests per second per IP)
    RATE_LIMIT_RPS: float = 5.0
    RATE_LIMIT_BURST: int = 20

    # GraphQL validation
    MAX_QUERY_DEPTH: int = 15
    MAX_QUERY_COMPLEXITY: int = 2000  # грубая оценка: количество узлов AST

    # APQ (Automatic Persisted Queries)
    APQ_ENABLED: bool = True
    APQ_CACHE_SIZE: int = 2000

    # Compression
    GZIP_MIN_SIZE: int = 1000

    # GraphiQL (доступно только в DEBUG)
    GRAPHQL_PLAYGROUND_PATH: str = "/graphiql"

    class Config:
        env_file = ".env"
        env_prefix = "GRAPHQL_"

    @validator("PORT")
    def _port_range(cls, v):
        if not (0 < v < 65536):
            raise ValueError("PORT must be in 1..65535")
        return v


settings = Settings()


# -----------------------------
# Logging
# -----------------------------

def configure_logging(debug: bool) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )


configure_logging(settings.DEBUG)
logger = logging.getLogger(settings.APP_NAME)


# -----------------------------
# Utilities: Request ID
# -----------------------------

REQUEST_ID_HEADER = "x-request-id"


def _gen_request_id() -> str:
    return hashlib.sha256(f"{time.time_ns()}-{os.getpid()}".encode()).hexdigest()[:16]


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get(REQUEST_ID_HEADER, _gen_request_id())
        request.state.request_id = rid
        response: Response = await call_next(request)
        response.headers[REQUEST_ID_HEADER] = rid
        return response


# -----------------------------
# Utilities: Token-bucket rate limiting (per IP)
# -----------------------------

class RateLimiterMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, rps: float, burst: int):
        super().__init__(app)
        self.rps = max(0.1, rps)
        self.capacity = max(1, burst)
        self._buckets: Dict[str, Tuple[float, float]] = {}  # ip -> (tokens, last_ts)
        self._lock = asyncio.Lock()

    async def dispatch(self, request: Request, call_next):
        if request.method != "OPTIONS":
            client_ip = request.client.host if request.client else "unknown"
            async with self._lock:
                tokens, last_ts = self._buckets.get(client_ip, (self.capacity, time.monotonic()))
                now = time.monotonic()
                # refill
                tokens = min(self.capacity, tokens + (now - last_ts) * self.rps)
                if tokens < 1.0:
                    # Too many requests
                    return JSONResponse(
                        {"error": "rate_limited", "detail": "Too many requests"},
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    )
                tokens -= 1.0
                self._buckets[client_ip] = (tokens, now)

        return await call_next(request)


# -----------------------------
# APQ cache (in-memory LRU)
# -----------------------------

class LRUAPQCache:
    def __init__(self, size: int):
        self.size = size
        self._store: Dict[str, str] = {}
        self._order: asyncio.Queue[str] = asyncio.Queue()

    def get(self, sha: str) -> Optional[str]:
        return self._store.get(sha)

    async def set(self, sha: str, query: str) -> None:
        if sha in self._store:
            return
        self._store[sha] = query
        await self._order.put(sha)
        # evict
        while len(self._store) > self.size:
            oldest = await self._order.get()
            self._store.pop(oldest, None)


apq_cache = LRUAPQCache(settings.APQ_CACHE_SIZE)


# -----------------------------
# GraphQL Schema
# -----------------------------

@strawberry.type
class Health:
    status: str
    version: str


@strawberry.type
class Query:
    @strawberry.field
    async def health(self) -> Health:
        return Health(status="ok", version="1.0.0")

    @strawberry.field
    async def echo(self, message: str) -> str:
        await asyncio.sleep(0)  # демонстрация async
        return message


@strawberry.type
class Mutation:
    @strawberry.mutation
    async def ping(self) -> str:
        return "pong"

    @strawberry.mutation
    async def add(self, a: int, b: int) -> int:
        return a + b


@strawberry.type
class Subscription:
    @strawberry.subscription
    async def ticker(self, interval_ms: int = 1000) -> str:
        i = 0
        while True:
            await asyncio.sleep(max(0.01, interval_ms / 1000))
            i += 1
            yield f"tick-{i}"


schema: BaseSchema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    subscription=Subscription,
)


# -----------------------------
# GraphQL Context
# -----------------------------

@dataclass
class GQLContext:
    request: Request
    settings: Settings
    logger: logging.Logger
    request_id: str


async def build_context(request: Request) -> GQLContext:
    rid = getattr(request.state, "request_id", _gen_request_id())
    return GQLContext(
        request=request,
        settings=settings,
        logger=logger,
        request_id=rid,
    )


# -----------------------------
# Error formatting
# -----------------------------

def format_errors(result: ExecutionResult, debug: bool) -> list[dict[str, Any]]:
    def _err_to_dict(err) -> dict[str, Any]:
        base = {"message": "Internal server error"}
        # Безопасный форматтер: в проде скрываем детали
        if debug:
            base["message"] = str(err)
            if getattr(err, "locations", None):
                base["locations"] = [{"line": loc.line, "column": loc.column} for loc in err.locations]  # type: ignore
            if getattr(err, "path", None):
                base["path"] = err.path
        else:
            # Включаем минимум диагностик без выдачи стека
            if getattr(err, "path", None):
                base["path"] = err.path
        # Тегируем request_id для трассировки
        base["extensions"] = {"request_id": "unknown"}
        return base

    errs = []
    for e in (result.errors or []):
        errs.append(_err_to_dict(e))
    return errs


# -----------------------------
# GraphQL validators: depth & complexity
# -----------------------------

class _DepthComplexityCounter:
    def __init__(self):
        self.max_depth = 0
        self.nodes = 0

    def count(self, document: DocumentNode) -> Tuple[int, int]:
        # считаем глубину и количество посещенных узлов
        current_depth = 0

        def enter(node, *_):
            self.nodes += 1
            nonlocal current_depth
            if isinstance(node, OperationDefinitionNode):
                current_depth = 0

        def leave(node, *_):
            nonlocal current_depth
            # глубину оцениваем по вложенности selectionSet
            selection_set = getattr(node, "selection_set", None)
            if selection_set and selection_set.selections:
                # when leaving a node that had children, reduce depth
                pass

        # Для глубины используем отдельный проход
        def measure_depth(node, depth: int):
            self.max_depth = max(self.max_depth, depth)
            selection_set = getattr(node, "selection_set", None)
            if selection_set and selection_set.selections:
                for child in selection_set.selections:
                    measure_depth(child, depth + 1)

        visit(document, enter=enter, leave=leave)
        # depth pass
        for defn in document.definitions:
            if isinstance(defn, OperationDefinitionNode):
                measure_depth(defn, 1)

        return self.max_depth, self.nodes


def validate_depth_complexity(query: str, max_depth: int, max_complexity: int) -> Tuple[bool, str]:
    try:
        doc = parse(query)
    except Exception as e:
        return False, f"Syntax error: {e}"

    counter = _DepthComplexityCounter()
    depth, nodes = counter.count(doc)

    if depth > max_depth:
        return False, f"Query depth {depth} exceeds limit {max_depth}"
    if nodes > max_complexity:
        return False, f"Query complexity {nodes} exceeds limit {max_complexity}"

    return True, "ok"


# -----------------------------
# App & Middleware
# -----------------------------

app = FastAPI(title=settings.APP_NAME, debug=settings.DEBUG)

# Middlewares
app.add_middleware(RequestIDMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[str(o) for o in settings.ALLOW_ORIGINS],
    allow_credentials=True,
    allow_methods=settings.ALLOW_METHODS,
    allow_headers=settings.ALLOW_HEADERS,
)
app.add_middleware(GZipMiddleware, minimum_size=settings.GZIP_MIN_SIZE)
app.add_middleware(RateLimiterMiddleware, rps=settings.RATE_LIMIT_RPS, burst=settings.RATE_LIMIT_BURST)


# -----------------------------
# Health endpoints
# -----------------------------

@app.get("/healthz", response_class=JSONResponse)
async def healthz(request: Request):
    return {
        "status": "ok",
        "service": settings.APP_NAME,
        "request_id": getattr(request.state, "request_id", "unknown"),
    }


@app.get("/readyz", response_class=PlainTextResponse)
async def readyz():
    return "ready"


# -----------------------------
# GraphiQL (DEV only)
# -----------------------------

GRAPHIQL_HTML = """
<!DOCTYPE html>
<html>
  <head>
    <title>GraphiQL</title>
    <meta charset="utf-8" />
    <meta name="robots" content="noindex" />
    <style>
      html, body, #graphiql { height: 100%; margin: 0; width: 100%; }
    </style>
    <link rel="stylesheet" href="https://unpkg.com/graphiql/graphiql.min.css" />
  </head>
  <body>
    <div id="graphiql">Loading...</div>
    <script
      crossorigin
      src="https://unpkg.com/react/umd/react.production.min.js">
    </script>
    <script
      crossorigin
      src="https://unpkg.com/react-dom/umd/react-dom.production.min.js">
    </script>
    <script src="https://unpkg.com/graphiql/graphiql.min.js"></script>
    <script>
      const fetcher = GraphiQL.createFetcher({ url: '/graphql' });
      ReactDOM.render(
        React.createElement(GraphiQL, { fetcher }),
        document.getElementById('graphiql'),
      );
    </script>
  </body>
</html>
"""

if settings.DEBUG and settings.GRAPHQL_PLAYGROUND_PATH:
    @app.get(settings.GRAPHQL_PLAYGROUND_PATH, include_in_schema=False)
    async def graphiql():
        return HTMLResponse(content=GRAPHIQL_HTML)


# -----------------------------
# GraphQL HTTP endpoint with APQ + validation
# -----------------------------

def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _extract_graphql_payload(body: Dict[str, Any]) -> Tuple[Optional[str], Dict[str, Any], Optional[str], Dict[str, Any]]:
    query = body.get("query")
    variables = body.get("variables") or {}
    operation_name = body.get("operationName")
    extensions = body.get("extensions") or {}
    return query, variables, operation_name, extensions


async def _resolve_apq(query: Optional[str], extensions: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """
    Возвращает (resolved_query, error_message)
    """
    if not settings.APQ_ENABLED:
        return query, None

    persisted = extensions.get("persistedQuery") if isinstance(extensions, dict) else None
    if not persisted:
        # не APQ запрос
        return query, None

    sha_from_client = persisted.get("sha256Hash")
    if not sha_from_client or not isinstance(sha_from_client, str):
        return None, "APQ: missing sha256Hash"

    if query:
        # Клиент прислал и query, и hash — сверим
        calc = _sha256(query)
        if calc != sha_from_client:
            return None, "APQ: sha256 mismatch"
        # Сохраняем в кэш
        await apq_cache.set(sha_from_client, query)
        return query, None

    # Только hash — пробуем найти
    cached = apq_cache.get(sha_from_client)
    if cached is None:
        return None, "APQ: persisted query not found"
    return cached, None


@app.post("/graphql")
async def graphql_endpoint(request: Request):
    rid = getattr(request.state, "request_id", "unknown")
    try:
        payload: Dict[str, Any] = await request.json()
    except Exception:
        return JSONResponse(
            {"errors": [{"message": "Invalid JSON", "extensions": {"request_id": rid}}]},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    query, variables, operation_name, extensions = _extract_graphql_payload(payload)

    # APQ support
    query, apq_err = await _resolve_apq(query, extensions)
    if apq_err:
        return JSONResponse(
            {"errors": [{"message": apq_err, "extensions": {"request_id": rid}}]},
            status_code=status.HTTP_200_OK,  # Apollo ожидает 200 с ошибкой APQ
        )

    if not query or not isinstance(query, str):
        return JSONResponse(
            {"errors": [{"message": "Query is required", "extensions": {"request_id": rid}}]},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Validation: depth & complexity
    ok, msg = validate_depth_complexity(
        query=query,
        max_depth=settings.MAX_QUERY_DEPTH,
        max_complexity=settings.MAX_QUERY_COMPLEXITY,
    )
    if not ok:
        return JSONResponse(
            {"errors": [{"message": msg, "extensions": {"request_id": rid}}]},
            status_code=status.HTTP_200_OK,
        )

    # Execute
    ctx = await build_context(request)
    try:
        result: ExecutionResult = await schema.execute(
            query,
            variable_values=variables,
            operation_name=operation_name,
            context_value=ctx,
        )
    except Exception as e:
        logger.exception("execution_failed", extra={"request_id": rid})
        return JSONResponse(
            {"errors": [{"message": "Internal server error", "extensions": {"request_id": rid}}]},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    response: Dict[str, Any] = {}
    if result.errors:
        response["errors"] = format_errors(result, debug=settings.DEBUG)
    if result.data is not None:
        response["data"] = result.data

    # Стандартный код 200 даже при GraphQL-ошибках
    return JSONResponse(response, status_code=status.HTTP_200_OK)


# -----------------------------
# WebSocket Subscriptions (via Strawberry ASGI app)
# -----------------------------
# Для подписок используем встроенный ASGI из Strawberry, монтируем отдельно,
# чтобы HTTP-пайплайн с кастомной валидацией/APQ не пересекался.

from strawberry.asgi import GraphQL as StrawberryGraphQL  # noqa: E402

strawberry_asgi_app = StrawberryGraphQL(
    schema,
    debug=settings.DEBUG,
    keep_alive=True,
)

app.routes.append(Mount("/graphql-ws", strawberry_asgi_app))


# -----------------------------
# Main entry
# -----------------------------

def _main() -> None:
    import uvicorn

    uvicorn.run(
        "server:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="debug" if settings.DEBUG else "info",
        workers=1,  # uvicorn workers + async = достаточно; далее под kubernetes/gunicorn
        factory=False,
    )


if __name__ == "__main__":
    _main()
