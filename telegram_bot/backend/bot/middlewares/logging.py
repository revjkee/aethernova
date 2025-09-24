import logging
from aiogram import BaseMiddleware
from aiogram.types import TelegramObject
from typing import Callable, Any, Awaitable

class LoggingMiddleware(BaseMiddleware):
    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict], Awaitable[Any]],
        event: TelegramObject,
        data: dict,
    ) -> Any:
        user = getattr(event.from_user, 'id', None) if hasattr(event, 'from_user') else None
        event_type = type(event).__name__
        logging.info(f"Event: {event_type} from user: {user}")
        return await handler(event, data)
