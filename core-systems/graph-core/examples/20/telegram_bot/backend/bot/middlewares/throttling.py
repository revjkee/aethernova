import time
from collections import defaultdict
from typing import Callable, Any, Awaitable

from aiogram import BaseMiddleware
from aiogram.types import TelegramObject, Message, CallbackQuery


class ThrottlingMiddleware(BaseMiddleware):
    """
    Middleware для ограничения частоты запросов (throttling).
    Ограничивает количество запросов от одного пользователя за заданный интервал.
    """

    def __init__(self, limit: int = 5, period: float = 1.0):
        super().__init__()
        self.limit = limit
        self.period = period
        self.users_requests = defaultdict(list)  # user_id -> list[timestamps]

    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict], Awaitable[Any]],
        event: TelegramObject,
        data: dict,
    ) -> Any:
        user_id = None
        if isinstance(event, (Message, CallbackQuery)):
            if event.from_user:
                user_id = event.from_user.id
        else:
            # Для прочих апдейтов пропускаем throttling
            return await handler(event, data)

        if user_id is None:
            return await handler(event, data)

        if data.get("bypass_throttling", False):
            return await handler(event, data)

        now = time.monotonic()
        timestamps = self.users_requests[user_id]

        # Очищаем старые запросы из списка
        while timestamps and timestamps[0] <= now - self.period:
            timestamps.pop(0)

        if len(timestamps) >= self.limit:
            # Достигнут лимит запросов — игнорируем или отправляем предупреждение
            if isinstance(event, Message):
                await event.answer("Слишком много запросов, подождите немного.")
            elif isinstance(event, CallbackQuery):
                await event.answer("Слишком много запросов, подождите немного.", show_alert=True)
            return  # Прекращаем обработку

        # Добавляем текущее время запроса
        timestamps.append(now)

        return await handler(event, data)
