# backend/main.py
import asyncio
import logging

from aiogram import Bot, Dispatcher
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.fsm.storage.redis import RedisStorage
from aiogram.types import BotCommand, BotCommandScopeDefault
from fastapi import FastAPI
from prometheus_fastapi_instrumentator import Instrumentator
from starlette_exporter import PrometheusMiddleware, handle_metrics
import uvicorn

from core.settings import config
from core.db import init_db
from backend.bot.router import setup_bot_router
from backend.bot.middlewares.throttling import ThrottlingMiddleware
from backend.core.logging_config import setup_logging

logger = logging.getLogger("backend_main")


bot_router = setup_bot_router()

def main():
    setup_logging()
    # запуск FastAPI или aiogram и т.д.
    
async def set_bot_commands(bot: Bot):
    """
    Устанавливает список команд бота в Telegram.
    """
    commands = [
        BotCommand(command="start", description="Запустить бота"),
        BotCommand(command="help", description="Помощь"),
        BotCommand(command="book", description="Записаться на услугу"),
        BotCommand(command="cancel", description="Отменить запись"),
        BotCommand(command="info", description="Информация о мастерах и слотах"),
    ]
    await bot.set_my_commands(commands, scope=BotCommandScopeDefault())
    logger.info("Commands set successfully.")


def create_app() -> FastAPI:
    """
    Создает FastAPI приложение с Prometheus и API-роутерами.
    """
    app = FastAPI(
        title="Client Booking API",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # middleware и endpoint для Prometheus
    app.add_middleware(PrometheusMiddleware)      # собирает HTTP-метрики
    app.add_route("/metrics", handle_metrics)     # отдаёт прометеусовские метрики

    # подключаем REST API роутеры
    from backend.api.v1.bookings import router as bookings_router
    from backend.api.v1.masters import router as masters_router
    from backend.api.v1.timeslots import router as timeslots_router

    app.include_router(bookings_router, prefix="/api/v1/bookings", tags=["bookings"])
    app.include_router(masters_router, prefix="/api/v1/masters", tags=["masters"])
    app.include_router(timeslots_router, prefix="/api/v1/timeslots", tags=["timeslots"])

    return app

app = create_app()

Instrumentator().instrument(app).expose(app)

async def main():
    """
    Основная функция запуска:
    - Инициализация БД
    - Настройка бота
    - Запуск FastAPI + Uvicorn
    """
    logging.basicConfig(level=logging.INFO)
    logger.info("Starting backend main...")

    # инициализируем БД
    await init_db()
    logger.info("Database initialized.")

    # создаём FastAPI приложение
    app = create_app()

    # настраиваем Telegram-бота
    session = AiohttpSession()
    storage = RedisStorage.from_url(settings.redis_url)
    bot = Bot(token=settings.telegram_token, session=session, parse_mode="HTML")
    dp = Dispatcher(storage=storage)
    dp.message.middleware(ThrottlingMiddleware(limit=5, key_prefix="throttle"))
    setup_bot_router(dp)
    await set_bot_commands(bot)

    # запускаем Uvicorn сервер (FastAPI + /metrics) и бот-поллинг
    config = uvicorn.Config(
        app,
        host=settings.api_host,
        port=settings.api_port,
        log_level="info",
    )
    server = uvicorn.Server(config)

    # запустим сервер в фоне, а затем бот-поллинг
    server_task = asyncio.create_task(server.serve())
    try:
        await dp.start_polling(bot)
    finally:
        # при завершении polling — корректно остановим Uvicorn
        server.should_exit = True
        await server_task
        await bot.session.close()
        await storage.close()
        logger.info("Shutdown complete.")

# Пример маршрута
@app.get("/")
async def root():
    return {"message": "Hello, world"}

if __name__ == "__main__":
    asyncio.run(main())
