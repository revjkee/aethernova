import asyncio
import logging
from typing import List, Optional

from aiogram import Bot
from aiogram.enums import ParseMode
from aiogram.types import Message

logger = logging.getLogger("notification_service")


class NotificationService:
    """
    Сервис для отправки уведомлений пользователям через Telegram бота.
    Поддерживает рассылки, индивидуальные уведомления и очереди.
    """

    def __init__(self, bot: Bot):
        self.bot = bot
        self._queue = asyncio.Queue()
        self._worker_task = None

    async def start_worker(self):
        """
        Запускает фоновый таск для отправки сообщений из очереди.
        """
        if self._worker_task is None or self._worker_task.done():
            self._worker_task = asyncio.create_task(self._worker())
            logger.info("Notification worker started.")

    async def stop_worker(self):
        """
        Останавливает фоновый таск и очищает очередь.
        """
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                logger.info("Notification worker cancelled.")
            self._worker_task = None
        while not self._queue.empty():
            self._queue.get_nowait()
            self._queue.task_done()

    async def _worker(self):
        """
        Фоновый таск, который последовательно отправляет сообщения из очереди.
        """
        while True:
            chat_id, text, parse_mode = await self._queue.get()
            try:
                await self.bot.send_message(chat_id, text, parse_mode=parse_mode)
                logger.debug(f"Sent notification to {chat_id}")
            except Exception as e:
                logger.error(f"Failed to send notification to {chat_id}: {e}")
            self._queue.task_done()
            await asyncio.sleep(0.05)  # throttle to avoid flooding

    async def send_message(self, chat_id: int, text: str, parse_mode: Optional[str] = ParseMode.HTML):
        """
        Немедленно отправляет сообщение через бота (без очереди).
        """
        try:
            await self.bot.send_message(chat_id, text, parse_mode=parse_mode)
            logger.debug(f"Sent direct message to {chat_id}")
        except Exception as e:
            logger.error(f"Failed to send direct message to {chat_id}: {e}")

    async def queue_message(self, chat_id: int, text: str, parse_mode: Optional[str] = ParseMode.HTML):
        """
        Добавляет сообщение в очередь на отправку.
        """
        await self._queue.put((chat_id, text, parse_mode))
        logger.debug(f"Queued message to {chat_id}")

    async def broadcast(self, chat_ids: List[int], text: str, parse_mode: Optional[str] = ParseMode.HTML):
        """
        Рассылает сообщение списку пользователей через очередь.
        """
        for chat_id in chat_ids:
            await self.queue_message(chat_id, text, parse_mode)
        logger.info(f"Broadcasted message to {len(chat_ids)} users.")


# Использование:
# notification_service = NotificationService(bot_instance)
# await notification_service.start_worker()
# await notification_service.queue_message(chat_id, "Текст уведомления")
# await notification_service.broadcast(list_of_ids, "Общее уведомление")
