from typing import List, Optional
from backend.models.master import Master  # ORM-модель мастера
from backend.models.booking import Booking  # ORM-модель записи
from backend.models.timeslot import Timeslot  # ORM-модель временного слота


class MasterService:
    """
    Сервис для работы с мастерами и доступным временем.
    """

    async def get_all_masters(self) -> List[Master]:
        """
        Получить список всех мастеров.
        """
        return await Master.all()

    async def get_master_by_name(self, name: str) -> Optional[Master]:
        """
        Получить мастера по имени.
        """
        try:
            master = await Master.get(name=name)
            return master
        except DoesNotExist:
            return None

    async def get_available_timeslots(
        self, master_id: int, date_str: str
    ) -> List[str]:
        """
        Получить список доступных временных слотов для мастера на дату.
        Исключить уже забронированные.
        """
        # Получаем все активные временные слоты
        slots = await TimeSlot.filter(is_active=True).order_by("start_time")

        # Получаем уже занятые слоты на дату у мастера
        booked_slots = await Booking.filter(master_id=master_id, date=date_str).values_list("time_slot", flat=True)

        # Формируем список доступных
        available = [
            slot.start_time.strftime("%H:%M")
            for slot in slots
            if slot.start_time.strftime("%H:%M") not in booked_slots
        ]

        return available

    async def update_master_info(self, master_id: int, **kwargs) -> bool:
        """
        Обновить информацию о мастере.
        """
        try:
            master = await Master.get(id=master_id)
            for key, value in kwargs.items():
                setattr(master, key, value)
            await master.save()
            return True
        except DoesNotExist:
            return False
