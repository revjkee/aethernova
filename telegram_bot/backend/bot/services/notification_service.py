from typing import Optional
from aiogram import Bot
from aiogram.types import ParseMode
import logging

class NotificationService:
    """
    Сервис для отправки уведомлений пользователям через Telegram Bot API.
    Позволяет отправлять текстовые сообщения с поддержкой Markdown и HTML.
    """

    def __init__(self, bot: Bot, logger: Optional[logging.Logger] = None):
        self.bot = bot
        self.logger = logger or logging.getLogger("notification_service")

    async def send_message(
        self,
        chat_id: int,
        text: str,
        parse_mode: Optional[ParseMode] = ParseMode.HTML,
        disable_web_page_preview: bool = True,
        disable_notification: bool = False,
    ) -> bool:
        """
        Отправляет сообщение пользователю.
        Возвращает True если успешно, False в случае ошибки.
        """

        try:
            await self.bot.send_message(
                chat_id=chat_id,
                text=text,
                parse_mode=parse_mode,
                disable_web_page_preview=disable_web_page_preview,
                disable_notification=disable_notification,
            )
            return True
        except Exception as e:
            self.logger.error(f"Failed to send message to {chat_id}: {e}", exc_info=True)
            return False

    async def notify_booking_created(self, chat_id: int, master_name: str, timeslot: str) -> bool:
        """
        Уведомление о создании записи.
        """
        text = (
            f"Ваша запись успешно создана!\n"
            f"Мастер: <b>{master_name}</b>\n"
            f"Время: <b>{timeslot}</b>"
        )
        return await self.send_message(chat_id=chat_id, text=text)

    async def notify_booking_canceled(self, chat_id: int, booking_id: int) -> bool:
        """
        Уведомление об отмене записи.
        """
        text = f"Ваша запись #{booking_id} была отменена."
        return await self.send_message(chat_id=chat_id, text=text)
