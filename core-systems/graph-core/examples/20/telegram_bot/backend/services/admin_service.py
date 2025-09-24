import logging
from typing import List
from backend.core.redis import RedisPool
from backend.models.master import MasterData
import orjson


class AdminService:
    def __init__(self, redis: RedisPool):
        self.redis = redis
        self.logger = logging.getLogger("AdminService")

    async def add_master(self, master: MasterData):
        key = f"master:{master.id}"
        await self.redis.set(key, orjson.dumps(master.dict()))
        self.logger.info(f"Добавлен мастер: {master.name} (id={master.id})")

    async def remove_master(self, master_id: int):
        key = f"master:{master_id}"
        result = await self.redis.delete(key)
        if result:
            self.logger.info(f"Удалён мастер с id={master_id}")
        else:
            self.logger.warning(f"Попытка удалить несуществующего мастера id={master_id}")

    async def list_masters(self) -> List[MasterData]:
        keys = await self.redis._redis.keys("master:*")
        masters = []
        for key in keys:
            raw = await self.redis.get(key)
            if raw:
                try:
                    masters.append(MasterData.parse_raw(raw))
                except Exception as e:
                    self.logger.warning(f"Ошибка разбора мастера из ключа {key}: {e}")
        self.logger.debug(f"Загружено мастеров: {len(masters)}")
        return masters
