from backend.models.timeslot import TimeSlot, TimeSlot_Pydantic, TimeSlotIn_Pydantic
from typing import List, Optional
import logging
from datetime import time

logger = logging.getLogger("timeslot_service")


class TimeSlotService:
    """
    Сервис для управления временными слотами.
    Включает создание, получение, обновление и удаление слотов.
    """

    @staticmethod
    async def create_timeslot(start_time: time, end_time: time, description: Optional[str] = None,
                              is_active: bool = True) -> TimeSlot_Pydantic:
        """
        Создаёт новый временной слот с валидацией, что start_time < end_time.
        """
        if start_time >= end_time:
            logger.error("Время начала слота должно быть меньше времени окончания.")
            raise ValueError("Время начала должно быть меньше времени окончания")

        # Проверка на пересечение с существующими слотами
        overlapping = await TimeSlot.filter(
            start_time__lt=end_time,
            end_time__gt=start_time
        ).exists()
        if overlapping:
            logger.error("Новый слот пересекается с существующим.")
            raise ValueError("Временной слот пересекается с уже существующим")

        timeslot_obj = await TimeSlot.create(
            start_time=start_time,
            end_time=end_time,
            description=description,
            is_active=is_active,
        )
        logger.info(f"Создан временной слот {timeslot_obj.id}: {start_time} - {end_time}.")
        return await TimeSlot_Pydantic.from_tortoise_orm(timeslot_obj)

    @staticmethod
    async def get_timeslot(timeslot_id: int) -> TimeSlot_Pydantic:
        """
        Получить временной слот по ID.
        """
        timeslot = await TimeSlot.get_or_none(id=timeslot_id)
        if not timeslot:
            logger.error(f"Временной слот с id {timeslot_id} не найден.")
            raise ValueError("Временной слот не найден")
        return await TimeSlot_Pydantic.from_tortoise_orm(timeslot)

    @staticmethod
    async def list_timeslots(active_only: bool = True) -> List[TimeSlot_Pydantic]:
        """
        Возвращает список временных слотов, по умолчанию только активных.
        """
        query = TimeSlot.all()
        if active_only:
            query = query.filter(is_active=True)
        timeslots = await query.order_by("start_time").all()
        return await TimeSlot_Pydantic.from_queryset(timeslots)

    @staticmethod
    async def update_timeslot(timeslot_id: int, **kwargs) -> TimeSlot_Pydantic:
        """
        Обновляет временной слот по переданным полям.
        Проверяет логику времени, если изменяются start_time или end_time.
        """
        timeslot = await TimeSlot.get_or_none(id=timeslot_id)
        if not timeslot:
            logger.error(f"Попытка обновления несуществующего временного слота {timeslot_id}.")
            raise ValueError("Временной слот не найден")

        start_time = kwargs.get("start_time", timeslot.start_time)
        end_time = kwargs.get("end_time", timeslot.end_time)

        if start_time >= end_time:
            logger.error("Время начала слота должно быть меньше времени окончания при обновлении.")
            raise ValueError("Время начала должно быть меньше времени окончания")

        # Проверка на пересечения с другими слотами (исключая текущий)
        overlapping = await TimeSlot.filter(
            start_time__lt=end_time,
            end_time__gt=start_time
        ).exclude(id=timeslot_id).exists()
        if overlapping:
            logger.error("Обновляемый слот пересекается с другим.")
            raise ValueError("Временной слот пересекается с другим слотом")

        for field, value in kwargs.items():
            if hasattr(timeslot, field):
                setattr(timeslot, field, value)

        try:
            await timeslot.save()
            logger.info(f"Временной слот {timeslot_id} успешно обновлен.")
        except IntegrityError as e:
            logger.error(f"Ошибка при обновлении временного слота {timeslot_id}: {e}")
            raise ValueError("Ошибка обновления временного слота")

        return await TimeSlot_Pydantic.from_tortoise_orm(timeslot)

    @staticmethod
    async def delete_timeslot(timeslot_id: int) -> bool:
        """
        Удаляет временной слот по ID.
        """
        deleted_count = await TimeSlot.filter(id=timeslot_id).delete()
        if deleted_count == 0:
            logger.error(f"Попытка удаления несуществующего временного слота {timeslot_id}.")
            raise ValueError("Временной слот не найден")
        logger.info(f"Временной слот {timeslot_id} удалён.")
        return True
