import logging
from typing import List
from backend.core.redis import RedisPool
from backend.models.timeslot import TimeslotData
import orjson


class TimeslotService:
    def __init__(self, redis: RedisPool):
        self.redis = redis
        self.logger = logging.getLogger("TimeslotService")

    async def add_timeslot(self, timeslot: TimeslotData):
        key = f"timeslot:{timeslot.id}"
        await self.redis.set(key, orjson.dumps(timeslot.dict()))
        self.logger.info(f"Добавлен слот: {timeslot.start_time}–{timeslot.end_time} (id={timeslot.id})")

    async def remove_timeslot(self, timeslot_id: int):
        key = f"timeslot:{timeslot_id}"
        result = await self.redis.delete(key)
        if result:
            self.logger.info(f"Удалён слот с id={timeslot_id}")
        else:
            self.logger.warning(f"Попытка удалить несуществующий слот id={timeslot_id}")

    async def list_timeslots(self) -> List[TimeslotData]:
        keys = await self.redis._redis.keys("timeslot:*")
        timeslots = []
        for key in keys:
            raw = await self.redis.get(key)
            if raw:
                try:
                    timeslots.append(TimeslotData.parse_raw(raw))
                except Exception as e:
                    self.logger.warning(f"Ошибка разбора слота из ключа {key}: {e}")
        self.logger.debug(f"Загружено слотов: {len(timeslots)}")
        return timeslots
