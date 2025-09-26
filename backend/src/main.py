import asyncio
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from src.auth import password_hasher
from src.db import database, init_db
from src.api import router as api_router
import logging

app = FastAPI(title="TeslaAI Genesis 2.0 API", version="2.0")

# Настройка CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # В проде ограничить по списку доменов
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Логирование
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("teslaai_main")

@app.on_event("startup")
async def startup_event():
    logger.info("Starting application")
    await init_db()
    await database.connect()

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down application")
    await database.disconnect()

# Подключение маршрутов API
app.include_router(api_router, prefix="/api/v1")
# Also include without version prefix for older frontend compatibility
app.include_router(api_router, prefix="/api")

# Пример корневого маршрута
@app.get("/")
async def root():
    return {"message": "TeslaAI Genesis 2.0 API is running."}
