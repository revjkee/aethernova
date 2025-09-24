# TeslaAI WebUI — Industrial Entrypoint v2.1
# Авторы: 20 агентов и 3 метагенерала
# FastAPI + Uvicorn + Middleware Stack + WebSocket + Templates + Secure Session

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.gzip import GZipMiddleware
import uvicorn
import logging

# Импорты маршрутов и middleware
from webui.routes.frontend_routes import router as frontend_router
from webui.routes.websocket_handlers import router as websocket_router
from webui.middleware.auth_guard import AuthGuardMiddleware

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TeslaAI-WebUI")

# Инициализация FastAPI
app = FastAPI(title="TeslaAI KeyVault WebUI", version="2.1.0", docs_url=None, redoc_url=None)

# === Middleware Stack ===
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(SessionMiddleware, secret_key="REPLACE_THIS_IN_PROD", session_cookie="session_token")
app.add_middleware(AuthGuardMiddleware)

# === Static Files & Templates ===
app.mount("/static", StaticFiles(directory="webui/static"), name="static")
templates = Jinja2Templates(directory="webui/templates")

# === Routers ===
app.include_router(frontend_router)
app.include_router(websocket_router)

# === Events ===
@app.on_event("startup")
async def startup_event():
    logger.info("WebUI startup initiated. Security modules loading...")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("WebUI shutdown complete. Resources released.")

# === Fallback Route ===
@app.get("/health")
async def healthcheck():
    return {"status": "ok", "version": "2.1.0"}

# === Main Entrypoint ===
if __name__ == "__main__":
    uvicorn.run("webui.web_ui:app", host="0.0.0.0", port=8080, reload=True)
