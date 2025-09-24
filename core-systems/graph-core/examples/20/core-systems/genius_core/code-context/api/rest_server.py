# genius-core/code-context/api/rest_server.py

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Dict, Optional
import uvicorn
import logging

from genius_core.code_context.indexer.index_engine import IndexEngine
from genius_core.code_context.search.semantic_search import SemanticSearch
from genius_core.code_context.agents.context_expander import ContextExpander
from genius_core.code_context.sync.delta_indexer import DeltaIndexer

app = FastAPI(
    title="TeslaAI GeniusCore - Code Context API",
    description="Industrial API for code semantic search, context expansion and indexing",
    version="2.0.0"
)

# Security middleware
token_auth_scheme = HTTPBearer()
VALID_TOKENS = {"teslaai-super-token"}  # to be replaced with vault/GPG in prod

# Logging setup
logger = logging.getLogger("code_context_api")
logging.basicConfig(level=logging.INFO)

# CORS for external tools
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # replace in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependencies
def validate_token(credentials: HTTPAuthorizationCredentials = Depends(token_auth_scheme)):
    token = credentials.credentials
    if token not in VALID_TOKENS:
        raise HTTPException(status_code=403, detail="Invalid token")

# Models
class IndexRequest(BaseModel):
    filepath: str

class SearchRequest(BaseModel):
    query: str
    top_k: int = 5

class ExpandRequest(BaseModel):
    symbol: str

# Engines
index_engine = IndexEngine()
search_engine = SemanticSearch()
expander = ContextExpander()
delta_indexer = DeltaIndexer()

# Routes
@app.post("/index", dependencies=[Depends(validate_token)])
def index_file(req: IndexRequest):
    logger.info(f"Indexing {req.filepath}")
    index_engine.index_file(req.filepath)
    return {"status": "indexed", "file": req.filepath}

@app.post("/search", dependencies=[Depends(validate_token)])
def search(req: SearchRequest):
    logger.info(f"Semantic search for: {req.query}")
    results = search_engine.search(req.query, req.top_k)
    return {"results": results}

@app.post("/expand", dependencies=[Depends(validate_token)])
def expand(req: ExpandRequest):
    logger.info(f"Expanding context for: {req.symbol}")
    ctx = expander.expand(req.symbol)
    return {"context": ctx}

@app.get("/health")
def health_check():
    return {"status": "ok", "version": app.version}

@app.get("/delta", dependencies=[Depends(validate_token)])
def delta_check():
    modified = delta_indexer.get_changes()
    return {"delta": modified}

# Entrypoint
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8899)
