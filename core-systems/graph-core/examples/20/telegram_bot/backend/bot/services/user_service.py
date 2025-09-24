from typing import Optional
from dataclasses import dataclass
from backend.core.redis import RedisPool
import orjson


@dataclass
class UserData:
    user_id: int
    username: Optional[str]
    full_name: Optional[str]


class UserService:
    """
    Сервис для работы с пользователями.
    Хранит и получает данные пользователей в Redis.
    """

    def __init__(self, redis: RedisPool):
        self.redis = redis

    async def save_user(self, user_id: int, username: Optional[str], full_name: Optional[str]) -> None:
        """
        Сохраняет информацию о пользователе.
        """
        key = f"user:{user_id}"
        data = {
            "user_id": user_id,
            "username": username,
            "full_name": full_name,
        }
        await self.redis.set(key, orjson.dumps(data))

    async def get_user(self, user_id: int) -> Optional[UserData]:
        """
        Получает данные пользователя по ID.
        """
        key = f"user:{user_id}"
        raw = await self.redis.get(key)
        if not raw:
            return None
        data = orjson.loads(raw)
        return UserData(**data)

    async def user_exists(self, user_id: int) -> bool:
        """
        Проверяет, есть ли пользователь в базе.
        """
        key = f"user:{user_id}"
        return bool(await self.redis.exists(key))
