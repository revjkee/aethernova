# TeslaAI Genesis — Central Error UI Handler v3.2
# Автор: Консилиум из 20 агентов и 3 метагенералов
# Назначение: Обработка и отрисовка ошибок в WebUI

from fastapi import Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.status import HTTP_403_FORBIDDEN, HTTP_404_NOT_FOUND, HTTP_500_INTERNAL_SERVER_ERROR
import logging

templates = Jinja2Templates(directory="webui/templates")
logger = logging.getLogger("webui.error_views")

def init_error_handlers(app):
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        code = exc.status_code
        logger.warning(f"[HTTP Error] {code} at {request.url.path} — {request.client.host}")
        return await render_error_page(request, code, detail=exc.detail)

    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        logger.error(f"[Unhandled Error] {request.url.path} — {request.client.host} — {str(exc)}")
        return await render_error_page(request, HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")

async def render_error_page(request: Request, code: int, detail: str = ""):
    """
    Рендер страницы ошибки.
    Параметры:
    - code: HTTP код ошибки
    - detail: описание (будет экранировано)
    """
    messages = {
        HTTP_403_FORBIDDEN: "Доступ запрещён",
        HTTP_404_NOT_FOUND: "Страница не найдена",
        HTTP_500_INTERNAL_SERVER_ERROR: "Внутренняя ошибка сервера"
    }
    return templates.TemplateResponse("error.html", {
        "request": request,
        "status_code": code,
        "message": messages.get(code, "Ошибка"),
        "detail": detail
    }, status_code=code)
