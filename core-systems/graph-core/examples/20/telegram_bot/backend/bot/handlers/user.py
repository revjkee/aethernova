from aiogram import Router, F
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton, WebAppInfo
from aiogram.fsm.context import FSMContext

from backend.bot.config import config
from backend.bot.services.booking_service import BookingService as BotBookingService
from backend.bot.keyboards.inline import user_menu_keyboard, timeslot_keyboard
from backend.core.redis import get_redis_pool

router = Router()


@router.message(Command("start"))
async def cmd_start(message: Message, state: FSMContext):
    # Приветствие пользователя и вывод главного меню
    await state.clear()
    kb = user_menu_keyboard()
    await message.answer("Добро пожаловать! Выберите действие:", reply_markup=kb)


@router.callback_query(F.data == "create_booking")
async def create_booking_menu(call: CallbackQuery):
    # Показать список доступных временных слотов через web_app
    webapp_url = f"{config.telegram_webapp_url}/?action=create_booking&user_id={call.from_user.id}"
    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="Открыть форму записи",
                    web_app=WebAppInfo(url=webapp_url)
                )
            ]
        ]
    )
    await call.message.answer("Заполните форму записи:", reply_markup=kb)
    await call.answer()


@router.callback_query(F.data == "view_bookings")
async def view_bookings(call: CallbackQuery):
    # Показать список текущих бронирований пользователя
    service = BotBookingService(redis=await get_redis_pool())
    bookings = await service.get_user_bookings(user_id=call.from_user.id)
    if not bookings:
        text = "У вас нет активных записей."
    else:
        text = "\n".join(f"#{b.id}: {b.master_name} в {b.timeslot}" for b in bookings)
    await call.message.answer(text)
    await call.answer()


@router.message(F.content_type == "web_app_data")
async def handle_webapp_data(message: Message):
    # Обработка данных из Telegram WebApp после заполнения формы
    data = message.web_app_data.data
    user_id = message.from_user.id
    master_id = int(data.get("master_id"))
    timeslot = data.get("timeslot")  # ISO строка
    service = BotBookingService(redis=await get_redis_pool())
    try:
        booking = await service.create_booking(user_id, master_id, timeslot)
    except Exception as e:
        await message.answer(f"Ошибка при создании записи: {e}")
    else:
        await message.answer(f"Запись создана: #{booking.id} у мастера {booking.master_name} в {booking.timeslot}")


@router.callback_query(F.data.startswith("cancel_"))
async def cancel_booking(call: CallbackQuery):
    # Отменить бронирование по callback_data cancel_<id>
    booking_id = int(call.data.split("_", 1)[1])
    service = BotBookingService(redis=await get_redis_pool())
    success = await service.cancel_booking(booking_id)
    if success:
        await call.message.answer(f"Бронирование #{booking_id} отменено.")
    else:
        await call.message.answer(f"Не удалось отменить запись #{booking_id}.")
    await call.answer()
