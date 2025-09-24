import asyncio
import logging

from aiogram import Bot, Dispatcher
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.client.default import DefaultBotProperties
from aiogram.fsm.storage.redis import RedisStorage

from backend.core.settings import settings
from backend.core.db import init_db
from backend.bot.router import setup_bot_router
from backend.bot.middlewares.throttling import ThrottlingMiddleware
from backend.core.logging_config import setup_logging

setup_logging()
logger = logging.getLogger("bot")  # или "api", "worker"

logger = logging.getLogger("run_bot")

logging.basicConfig(level=logging.DEBUG)

async def main():
    logging.basicConfig(level=logging.INFO)
    logger.info("Starting Telegram bot...")

    await init_db()
    logger.info("Database initialized.")

    session = AiohttpSession()
    storage = RedisStorage.from_url(settings.redis_url)

    bot = Bot(
        token=settings.telegram_token,
        session=session, 
        default=DefaultBotProperties(parse_mode="HTML")
    )
    dp = Dispatcher(storage=storage)

    dp.message.middleware(ThrottlingMiddleware(limit=5))
    router = setup_bot_router()
    dp.include_router(router)

    try:
        await dp.start_polling(bot)
    finally:
        await bot.session.close()
        await storage.close()
        logger.info("Telegram bot stopped.")


if __name__ == "__main__":
    asyncio.run(main())
