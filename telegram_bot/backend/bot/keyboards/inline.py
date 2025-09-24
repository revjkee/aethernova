from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from typing import List


def user_menu_keyboard() -> InlineKeyboardMarkup:
    buttons = [
        [
            InlineKeyboardButton(text="Записаться", callback_data="create_booking"),
            InlineKeyboardButton(text="Мои записи", callback_data="view_bookings"),
        ]
    ]
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def admin_menu_keyboard() -> InlineKeyboardMarkup:
    buttons = [
        [
            InlineKeyboardButton(text="Управление мастерами", callback_data="manage_masters"),
            InlineKeyboardButton(text="Управление слотами", callback_data="manage_timeslots"),
        ],
        [
            InlineKeyboardButton(text="Все бронирования", callback_data="list_bookings_admin"),
        ],
    ]
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def master_keyboard(masters: List[dict]) -> InlineKeyboardMarkup:
    buttons = [
        [InlineKeyboardButton(
            text=f"{master['name']} (ID: {master['id']})",
            callback_data=f"delete_master_{master['id']}"
        )] for master in masters
    ]
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def timeslot_keyboard(timeslots: List[dict]) -> InlineKeyboardMarkup:
    buttons = [
        [InlineKeyboardButton(
            text=f"{slot['start_time']} - {slot['end_time']}",
            callback_data=f"delete_timeslot_{slot['id']}"
        )] for slot in timeslots
    ]
    return InlineKeyboardMarkup(inline_keyboard=buttons)
