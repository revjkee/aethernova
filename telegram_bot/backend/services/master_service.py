from datetime import time, date
from sqlalchemy import select, and_
from backend.models.timeslot import Timeslot
from backend.models.booking import Booking

DEFAULT_MASTERS = ["Алиса", "Алексей", "Полина", "Настя", "Дарья"]
DEFAULT_TIMES = [time(8,0), time(10,0), time(12,0), time(14,0), time(16,0), time(18,0), time(20,0)]


class MasterService:
    # твои уже написанные методы...

    @staticmethod
    async def init_default_masters(session: AsyncSession):
        for name in DEFAULT_MASTERS:
            q = select(Master).where(Master.name == name)
            result = await session.execute(q)
            if not result.scalars().first():
                new_master = Master(name=name, is_active=True)
                session.add(new_master)
        await session.commit()

    @staticmethod
    async def init_default_timeslots(session: AsyncSession):
        for start in DEFAULT_TIMES:
            q = select(Timeslot).where(Timeslot.start_time == start)
            result = await session.execute(q)
            if not result.scalars().first():
                new_slot = Timeslot(start_time=start, end_time=(time(start.hour+2, 0)), is_active=True)
                session.add(new_slot)
        await session.commit()

    @staticmethod
    async def get_available_timeslots(session: AsyncSession, master_id: int, on_date: date) -> list[Timeslot]:
        """
        Возвращает список временных слотов, на которые мастер доступен (без бронирования) на указанную дату.
        """
        # Получаем все активные таймслоты
        q_all = select(Timeslot).where(Timeslot.is_active == True)
        result_all = await session.execute(q_all)
        all_slots = result_all.scalars().all()

        # Получаем слоты, занятые на дату для мастера
        q_booked = select(Booking.timeslot_id).where(
            and_(
                Booking.master_id == master_id,
                Booking.date == on_date,
                Booking.confirmed == True,
            )
        )
        result_booked = await session.execute(q_booked)
        booked_slot_ids = set(result_booked.scalars().all())

        # Фильтруем доступные
        available = [slot for slot in all_slots if slot.id not in booked_slot_ids]
        return available
