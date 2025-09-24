from aiogram import BaseMiddleware
from aiogram.types import Message, CallbackQuery, TelegramObject
from typing import Callable, Any


class ReplyMiddleware(BaseMiddleware):
    """
    Middleware, который автоматически отвечает на сообщения и колбэки,
    если у обработчика нет собственного ответа (например, inline query).
    """

    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict], Any],
        event: TelegramObject,
        data: dict,
    ) -> Any:
        response = await handler(event, data)

        # Если это Message и обработчик не отправил ответа, отправляем стандартный
        if isinstance(event, Message) and response is None:
            await event.answer("Сообщение получено, но пока нет готового ответа.")

        # Если это CallbackQuery и не было ответа, отвечаем для снятия "часика"
        if isinstance(event, CallbackQuery) and response is None:
            await event.answer()

        return response
