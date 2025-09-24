# genius-core/code-context/api/graphql_adapter.py

import strawberry
from fastapi import APIRouter
from strawberry.fastapi import GraphQLRouter
from typing import List

from genius_core.code_context.search.semantic_search import SemanticSearch
from genius_core.code_context.indexer.index_engine import IndexEngine
from genius_core.code_context.agents.code_summary_agent import summarize_code
from genius_core.code_context.sync.dag_tracker import get_dag_version_info

# Core engines
search_engine = SemanticSearch()
index_engine = IndexEngine()

# ==== SCHEMA ====

@strawberry.type
class SearchResult:
    path: str
    score: float
    snippet: str

@strawberry.type
class VersionInfo:
    path: str
    hash: str
    timestamp: str

@strawberry.type
class Query:

    @strawberry.field
    def semantic_search(self, query: str, top_k: int = 5) -> List[SearchResult]:
        results = search_engine.search(query, top_k)
        return [SearchResult(path=r['path'], score=r['score'], snippet=r['snippet']) for r in results]

    @strawberry.field
    def summarize(self, path: str) -> str:
        code = index_engine.load_code(path)
        return summarize_code(code)

    @strawberry.field
    def version_info(self, path: str) -> VersionInfo:
        info = get_dag_version_info(path)
        return VersionInfo(path=info['path'], hash=info['hash'], timestamp=info['timestamp'])

# ==== ROUTER ====

schema = strawberry.Schema(query=Query)
graphql_app = GraphQLRouter(schema)

router = APIRouter()
router.include_router(graphql_app, prefix="/graphql")

