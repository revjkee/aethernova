from aiogram import Router, F
from aiogram.types import Message, CallbackQuery
from aiogram.fsm.context import FSMContext
from aiogram.filters import Command

from backend.bot.services.booking_service import BookingService as BotBookingService
from backend.bot.services.master_service import MasterService as BotMasterService
from backend.bot.keyboards.inline import admin_menu_keyboard, master_keyboard, timeslot_keyboard
from backend.core.redis import get_redis_pool

router = Router()


@router.message(Command("admin"))
async def cmd_admin(message: Message, state: FSMContext):
    # Приветствие админа и показ меню управления
    await state.clear()
    kb = admin_menu_keyboard()
    await message.answer("Админ-панель: выберите действие", reply_markup=kb)


@router.callback_query(F.data == "list_bookings_admin")
async def list_all_bookings(call: CallbackQuery):
    # Показать все бронирования (ID, пользователь, мастер, время)
    service = BotBookingService(redis=await get_redis_pool())
    bookings = await service.list_all_bookings()
    if not bookings:
        text = "Нет активных бронирований."
    else:
        text = "\n".join(
            f"#{b.id}: User {b.user_id}, Master {b.master_name}, {b.timeslot}"
            for b in bookings
        )
    await call.message.answer(text)
    await call.answer()


@router.callback_query(F.data == "manage_masters")
async def manage_masters(call: CallbackQuery):
    # Показать список мастеров с inline-кнопками для удаления
    service = BotMasterService(redis=await get_redis_pool())
    masters = await service.list_masters()
    kb = master_keyboard(masters)
    await call.message.answer("Управление мастерами:", reply_markup=kb)
    await call.answer()


@router.callback_query(F.data.startswith("delete_master_"))
async def delete_master(call: CallbackQuery):
    # Удалить мастера по callback_data delete_master_<id>
    master_id = int(call.data.split("_", 2)[2])
    service = BotMasterService(redis=await get_redis_pool())
    success = await service.delete_master(master_id)
    if success:
        await call.message.answer(f"Мастер #{master_id} удалён")
    else:
        await call.message.answer(f"Не удалось удалить мастера #{master_id}")
    await call.answer()


@router.callback_query(F.data == "manage_timeslots")
async def manage_timeslots(call: CallbackQuery):
    # Показать все слоты времени с кнопками управления
    from backend.bot.services.timeslot_service import TimeslotService as BotTimeslotService
    service = BotTimeslotService(redis=await get_redis_pool())
    slots = await service.list_timeslots()
    kb = timeslot_keyboard(slots)
    await call.message.answer("Управление слотами времени:", reply_markup=kb)
    await call.answer()


@router.callback_query(F.data.startswith("delete_timeslot_"))
async def delete_timeslot(call: CallbackQuery):
    # Удалить слот по callback_data delete_timeslot_<id>
    timeslot_id = int(call.data.split("_", 2)[2])
    from backend.bot.services.timeslot_service import TimeslotService as BotTimeslotService
    service = BotTimeslotService(redis=await get_redis_pool())
    success = await service.delete_timeslot(timeslot_id)
    if success:
        await call.message.answer(f"Слот #{timeslot_id} удалён")
    else:
        await call.message.answer(f"Не удалось удалить слот #{timeslot_id}")
    await call.answer()
