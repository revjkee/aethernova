# genius-core/code-context/ui/web_ui.py

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from pydantic import BaseModel

from genius_core.code_context.search.semantic_search import SemanticSearch
from genius_core.code_context.agents.code_summary_agent import summarize_code
from genius_core.code_context.sync.dag_tracker import get_dag_version_info

# Инициализация
router = APIRouter()
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Подключение статики (css/js/icons)
router.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

search_engine = SemanticSearch()

# ======== МОДЕЛИ ========
class SearchQuery(BaseModel):
    query: str
    top_k: int = 5

class SummarizeRequest(BaseModel):
    path: str

class VersionRequest(BaseModel):
    path: str

# ======== РОУТЫ ========

@router.get("/", response_class=HTMLResponse)
async def ui_index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@router.post("/search")
async def search_endpoint(query: SearchQuery):
    results = search_engine.search(query.query, top_k=query.top_k)
    return JSONResponse(content=results)

@router.post("/summarize")
async def summarize_endpoint(req: SummarizeRequest):
    code = search_engine.load_code(req.path)
    summary = summarize_code(code)
    return JSONResponse(content={"summary": summary})

@router.post("/version")
async def version_endpoint(req: VersionRequest):
    version_info = get_dag_version_info(req.path)
    return JSONResponse(content=version_info)

