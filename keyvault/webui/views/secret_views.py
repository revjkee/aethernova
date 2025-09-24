# TeslaAI Genesis — WebUI View Handler v2.5
# Обработка операций над ключами через Web-интерфейс

from fastapi import APIRouter, Request, Form, Depends, HTTPException, status
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from keyvault.webui.security.session_manager import get_current_user
from keyvault.core.secret_manager import get_secret, create_secret, delete_secret, list_secrets
from keyvault.audit.audit_logger import log_action
from keyvault.webui.security.csrf_protection import validate_csrf
from starlette.status import HTTP_403_FORBIDDEN

router = APIRouter()
templates = Jinja2Templates(directory="webui/templates")

@router.get("/secrets", response_class=HTMLResponse)
async def secrets_page(request: Request, user: str = Depends(get_current_user)):
    secrets = await list_secrets(user)
    return templates.TemplateResponse("secrets.html", {"request": request, "secrets": secrets, "user": user})

@router.post("/secrets/create")
async def create_secret_handler(
    request: Request,
    name: str = Form(...),
    value: str = Form(...),
    csrf_token: str = Form(...),
    user: str = Depends(get_current_user)
):
    validate_csrf(request, csrf_token)
    await create_secret(user, name, value)
    await log_action(user, "create_secret", {"name": name})
    return RedirectResponse(url="/secrets", status_code=303)

@router.post("/secrets/delete")
async def delete_secret_handler(
    request: Request,
    name: str = Form(...),
    csrf_token: str = Form(...),
    user: str = Depends(get_current_user)
):
    validate_csrf(request, csrf_token)
    result = await delete_secret(user, name)
    if not result:
        raise HTTPException(status_code=404, detail="Secret not found")
    await log_action(user, "delete_secret", {"name": name})
    return RedirectResponse(url="/secrets", status_code=303)

@router.get("/secrets/view")
async def view_secret_handler(
    request: Request,
    name: str,
    user: str = Depends(get_current_user)
):
    secret = await get_secret(user, name)
    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")
    await log_action(user, "view_secret", {"name": name})
    return templates.TemplateResponse("secret_detail.html", {"request": request, "secret": secret, "user": user})
