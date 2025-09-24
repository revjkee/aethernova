import asyncio
import logging
from backend.core.settings import settings
from backend.core.db import init_db
from backend.core.message_queue import MessageQueue
from backend.services.notification_service import NotificationService
from aiogram import Bot
from aiogram.client.default import DefaultBotProperties  # импорт для новых настроек по умолчанию
from backend.core.logging_config import setup_logging

setup_logging()
logger = logging.getLogger("bot")  # или "api", "worker"

logger = logging.getLogger("run_worker")


async def main():
    logging.basicConfig(level=logging.INFO)
    logger.info("Starting background worker...")

    await init_db()
    logger.info("Database initialized.")

    bot = Bot(
        token=settings.telegram_token,
        default=DefaultBotProperties(parse_mode="HTML")  # правильный способ задать parse_mode
    )
    notification_service = NotificationService(bot)
    await notification_service.start_worker()

    try:
        # Основной цикл воркера — заглушка для поддержания процесса живым
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        logger.info("Worker shutdown requested.")
    finally:
        await notification_service.stop_worker()
        await bot.session.close()
        logger.info("Background worker stopped.")


if __name__ == "__main__":
    asyncio.run(main())
