# TeslaAI WebUI Secure Frontend Router v2.0
# Поддержка Jinja2, шаблонов, безопасной маршрутизации
# Проверено: 20 агентов + 3 метагенерала

from fastapi import APIRouter, Request, Depends, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from keyvault.api.auth_middleware import get_current_user
from keyvault.audit.audit_logger import log_event
from keyvault.access.context_fingerprint import get_context_hash

import logging

logger = logging.getLogger("frontend_router")

router = APIRouter()
templates = Jinja2Templates(directory="webui/templates")

SAFE_PAGES = {
    "index": "index.html",
    "secrets": "secrets.html",
    "audit": "audit.html",
    "error": "error.html"
}


def validate_page_name(page: str) -> str:
    if page not in SAFE_PAGES:
        raise StarletteHTTPException(status_code=404, detail="Page not found")
    return SAFE_PAGES[page]


@router.get("/", response_class=HTMLResponse)
async def get_index(request: Request, user=Depends(get_current_user)):
    context_hash = await get_context_hash(request)
    await log_event(user, "access_ui", {"page": "index", "context": context_hash})
    return templates.TemplateResponse("index.html", {"request": request, "user": user})


@router.get("/ui/{page}", response_class=HTMLResponse)
async def get_ui_page(request: Request, page: str, user=Depends(get_current_user)):
    page_template = validate_page_name(page)
    context_hash = await get_context_hash(request)
    await log_event(user, "access_ui", {"page": page, "context": context_hash})
    return templates.TemplateResponse(page_template, {"request": request, "user": user})


@router.get("/unauthorized", response_class=HTMLResponse)
async def unauthorized_page(request: Request):
    return templates.TemplateResponse("error.html", {"request": request})


@router.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    logger.warning(f"HTTP Exception: {exc.status_code} on {request.url}")
    return templates.TemplateResponse("error.html", {"request": request}, status_code=exc.status_code)
