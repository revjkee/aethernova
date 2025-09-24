from backend.models.booking import Booking_Pydantic, BookingIn_Pydantic
from backend.models.master import Master
from backend.models.timeslot import TimeSlot
from typing import List, Optional
from datetime import date
import logging


logger = logging.getLogger("booking_service")


class BookingService:
    """
    Сервис для управления записями клиентов.
    Включает создание, получение, обновление и удаление записей.
    """

    @staticmethod
    async def create_booking(client_name: str, client_phone: str, master_id: int, booking_date: date,
                             time_slot: str, notes: Optional[str] = None) -> Booking_Pydantic:
        """
        Создает новую запись, проверяя существование мастера и уникальность слота.
        """
        try:
            master = await Master.get(id=master_id, is_active=True)
        except DoesNotExist:
            logger.error(f"Мастер с id {master_id} не найден или не активен.")
            raise ValueError("Мастер не найден или не активен")

        # Проверка, что слот существует и активен
        slot_exists = await TimeSlot.exists(start_time=time_slot, is_active=True)
        if not slot_exists:
            logger.error(f"Временной слот {time_slot} не найден или не активен.")
            raise ValueError("Временной слот не найден или не активен")

        # Проверка уникальности записи
        existing = await Booking.filter(master_id=master_id, date=booking_date, time_slot=time_slot).exists()
        if existing:
            logger.error(f"Слот {time_slot} на {booking_date} у мастера {master_id} уже занят.")
            raise ValueError("Данный временной слот уже занят")

        booking_obj = await Booking.create(
            client_name=client_name,
            client_phone=client_phone,
            master_id=master_id,
            date=booking_date,
            time_slot=time_slot,
            notes=notes,
        )
        logger.info(f"Создана запись {booking_obj.id} для клиента {client_name}.")
        return await Booking_Pydantic.from_tortoise_orm(booking_obj)

    @staticmethod
    async def get_booking(booking_id: int) -> Booking_Pydantic:
        """
        Получить запись по ID.
        """
        booking = await Booking.get_or_none(id=booking_id)
        if not booking:
            logger.error(f"Запись с id {booking_id} не найдена.")
            raise ValueError("Запись не найдена")
        return await Booking_Pydantic.from_tortoise_orm(booking)

    @staticmethod
    async def list_bookings(master_id: Optional[int] = None, booking_date: Optional[date] = None) -> List[Booking_Pydantic]:
        """
        Список записей с опциональной фильтрацией по мастеру и дате.
        """
        query = Booking.all()
        if master_id is not None:
            query = query.filter(master_id=master_id)
        if booking_date is not None:
            query = query.filter(date=booking_date)
        bookings = await query.order_by("date", "time_slot").all()
        return await Booking_Pydantic.from_queryset(bookings)

    @staticmethod
    async def update_booking(booking_id: int, **kwargs) -> Booking_Pydantic:
        """
        Обновляет запись с передачей полей через kwargs.
        """
        booking = await Booking.get_or_none(id=booking_id)
        if not booking:
            logger.error(f"Попытка обновления несуществующей записи {booking_id}.")
            raise ValueError("Запись не найдена")

        # Не допускаем изменение мастера и даты на конфликтующие значения (можно доработать)
        for field, value in kwargs.items():
            setattr(booking, field, value)

        try:
            await booking.save()
            logger.info(f"Запись {booking_id} успешно обновлена.")
        except IntegrityError as e:
            logger.error(f"Ошибка при обновлении записи {booking_id}: {e}")
            raise ValueError("Ошибка обновления записи")

        return await Booking_Pydantic.from_tortoise_orm(booking)

    @staticmethod
    async def delete_booking(booking_id: int) -> bool:
        """
        Удаляет запись по ID.
        """
        deleted_count = await Booking.filter(id=booking_id).delete()
        if deleted_count == 0:
            logger.error(f"Попытка удаления несуществующей записи {booking_id}.")
            raise ValueError("Запись не найдена")
        logger.info(f"Запись {booking_id} удалена.")
        return True
