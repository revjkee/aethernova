from aiogram import BaseMiddleware
from aiogram.types import Message, CallbackQuery
from typing import Callable, Any

class AuthMiddleware(BaseMiddleware):
    def __init__(self, allowed_user_ids: set[int] = set()):
        super().__init__()
        self.allowed_user_ids = allowed_user_ids

    async def __call__(
        self,
        handler: Callable,
        event: Message | CallbackQuery,
        data: dict[str, Any]
    ):
        user_id = None
        if isinstance(event, Message):
            user_id = event.from_user.id
        elif isinstance(event, CallbackQuery):
            user_id = event.from_user.id

        if self.allowed_user_ids and user_id not in self.allowed_user_ids:
            # Прерываем обработку, не вызывая handler
            return  # либо return None

        return await handler(event, data)
