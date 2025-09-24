# TeslaAI Genesis — Audit View Handler v2.7
# Обработка UI-запросов на просмотр журналов действий

from fastapi import APIRouter, Request, Depends, Query
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from keyvault.audit.access_history import get_user_audit_log
from keyvault.webui.security.session_manager import get_current_user
from typing import Optional

router = APIRouter()
templates = Jinja2Templates(directory="webui/templates")

@router.get("/audit", response_class=HTMLResponse)
async def audit_page(
    request: Request,
    user: str = Depends(get_current_user),
    event_type: Optional[str] = Query(default=None),
    target: Optional[str] = Query(default=None),
    limit: int = Query(default=50, le=200)
):
    """
    Просмотр журналов аудита:
    - Фильтрация по типу события (view_secret, create_secret, delete_secret, etc.)
    - Фильтрация по целевому ключу
    - Максимум 200 записей
    """
    audit_log = await get_user_audit_log(user, event_filter=event_type, target_filter=target, limit=limit)
    return templates.TemplateResponse("audit.html", {
        "request": request,
        "audit_log": audit_log,
        "user": user,
        "filters": {
            "event_type": event_type,
            "target": target,
            "limit": limit
        }
    })
