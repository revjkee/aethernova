import logging
from aiogram import BaseMiddleware
from aiogram.types import TelegramObject
from aiogram.exceptions import TelegramAPIError, TelegramForbiddenError
from typing import Callable, Any, Awaitable

class ErrorHandlerMiddleware(BaseMiddleware):
    def __init__(self, logger: logging.Logger = None):
        super().__init__()
        self.logger = logger or logging.getLogger("aiogram_error_handler")

    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict], Awaitable[Any]],
        event: TelegramObject,
        data: dict,
    ) -> Any:
        try:
            return await handler(event, data)
        except TelegramForbiddenError:
            user_id = getattr(event.from_user, 'id', 'unknown')
            self.logger.info(f"User blocked bot: {user_id}")
        except TelegramAPIError as e:
            self.logger.warning(f"Telegram API error: {e} (event={event})")
        except Exception as e:
            self.logger.error(f"Unhandled exception: {e} (event={event})", exc_info=True)
        return None
