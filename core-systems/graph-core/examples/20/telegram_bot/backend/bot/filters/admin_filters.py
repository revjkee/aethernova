from aiogram.filters import BaseFilter
from aiogram.types import Message, CallbackQuery
from typing import Union


class AdminFilter(BaseFilter):
    """
    Фильтр для проверки, является ли пользователь администратором.
    """

    def __init__(self, admin_ids: set[int]):
        self.admin_ids = admin_ids

    async def __call__(self, obj: Union[Message, CallbackQuery]) -> bool:
        user_id = None
        if isinstance(obj, Message) and obj.from_user:
            user_id = obj.from_user.id
        elif isinstance(obj, CallbackQuery) and obj.from_user:
            user_id = obj.from_user.id
        return user_id in self.admin_ids if user_id else False
