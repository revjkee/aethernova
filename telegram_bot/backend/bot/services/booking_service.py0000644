from typing import List, Optional
from datetime import datetime
import orjson
import logging

from backend.core.redis import RedisPool
from backend.models.booking import BookingData
from backend.models.master import MasterData
from backend.models.timeslot import TimeslotData


class BookingService:
    """
    Сервис для работы с бронированиями в Redis.
    Ключи:
        - booking:<master_id>:<timeslot>
        - booking:data:<booking_id>
        - user_bookings:<user_id>
    """

    def __init__(self, redis: RedisPool):
        self.redis = redis
        self.logger = logging.getLogger("BookingService")

    async def create_booking(self, user_id: int, master_id: int, timeslot: str) -> BookingData:
        key_slot = f"booking:{master_id}:{timeslot}"
        exists = await self.redis.exists(key_slot)
        if exists:
            self.logger.warning(f"Слот уже занят: {key_slot}")
            raise Exception("Слот уже забронирован")

        booking_id = await self.redis.incr("booking:id_seq")
        booking_data = BookingData(
            id=booking_id,
            user_id=user_id,
            master_id=master_id,
            timeslot=timeslot,
            created_at=datetime.utcnow(),
        )

        pipe = await self.redis.pipeline()
        pipe.set(key_slot, booking_id, ex=60 * 60 * 24 * 30)
        pipe.set(f"booking:data:{booking_id}", orjson.dumps(booking_data.dict()), ex=60 * 60 * 24 * 30)
        pipe.sadd(f"user_bookings:{user_id}", booking_id)
        await pipe.execute()

        self.logger.info(f"Создана бронь #{booking_id} для user={user_id}, мастер={master_id}, слот={timeslot}")
        return booking_data

    async def get_booking(self, booking_id: int) -> Optional[BookingData]:
        key = f"booking:data:{booking_id}"
        raw = await self.redis.get(key)
        if not raw:
            self.logger.debug(f"Бронирование не найдено: {key}")
            return None
        try:
            data = orjson.loads(raw)
            return BookingData.parse_obj(data)
        except Exception as e:
            self.logger.error(f"Ошибка при разборе брони {booking_id}: {e}")
            return None

    async def get_user_bookings(self, user_id: int) -> List[BookingData]:
        key = f"user_bookings:{user_id}"
        ids = await self.redis.smembers(key)
        bookings = []
        for bid in ids:
            try:
                booking = await self.get_booking(int(bid))
                if booking:
                    bookings.append(booking)
            except Exception as e:
                self.logger.warning(f"Ошибка загрузки брони id={bid} для user={user_id}: {e}")
        return bookings

    async def cancel_booking(self, booking_id: int) -> bool:
        booking = await self.get_booking(booking_id)
        if not booking:
            self.logger.info(f"Попытка отмены несуществующей брони: {booking_id}")
            return False

        pipe = await self.redis.pipeline()
        pipe.delete(f"booking:{booking.master_id}:{booking.timeslot}")
        pipe.delete(f"booking:data:{booking_id}")
        pipe.srem(f"user_bookings:{booking.user_id}", booking_id)
        await pipe.execute()

        self.logger.info(f"Бронь #{booking_id} отменена пользователем {booking.user_id}")
        return True

    async def list_all_bookings(self) -> List[BookingData]:
        cursor = 0
        bookings = []
        try:
            while True:
                cursor, keys = await self.redis._redis.scan(cursor=cursor, match="booking:data:*", count=100)
                for key in keys:
                    raw = await self.redis.get(key)
                    if raw:
                        try:
                            bookings.append(BookingData.parse_raw(raw))
                        except Exception as e:
                            self.logger.warning(f"Ошибка парсинга при list_all_bookings: ключ={key}, ошибка={e}")
                if cursor == 0:
                    break
        except Exception as e:
            self.logger.error(f"Ошибка сканирования всех бронирований: {e}")
        return bookings
