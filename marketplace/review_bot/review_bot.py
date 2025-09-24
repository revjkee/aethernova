# /marketplace/review-bot/review_bot.py
import asyncio
from typing import List, Optional
from aiogram import Bot, Dispatcher, types
from aiogram.contrib.fsm_storage.memory import MemoryStorage
from aiogram.dispatcher import FSMContext
from aiogram.dispatcher.filters.state import State, StatesGroup
from aiogram.utils import executor
from pydantic import BaseModel, ValidationError
import logging

# Конфигурация логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Настройки бота (токен должен быть безопасно загружен из env)
API_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"

bot = Bot(token=API_TOKEN)
storage = MemoryStorage()
dp = Dispatcher(bot, storage=storage)

# Модель отзыва
class Review(BaseModel):
    user_id: int
    username: Optional[str]
    rating: int  # от 1 до 5
    comment: Optional[str]

# Состояния FSM для сбора отзыва
class ReviewStates(StatesGroup):
    waiting_for_rating = State()
    waiting_for_comment = State()

# Хранилище отзывов (в реальном проекте заменить на БД)
reviews_storage: List[Review] = []

# Команда /start и /review
@dp.message_handler(commands=['start'])
async def start_handler(message: types.Message):
    await message.answer(
        "Привет! Этот бот собирает отзывы о товарах маркетплейса.\n"
        "Чтобы оставить отзыв, напишите команду /review"
    )

@dp.message_handler(commands=['review'])
async def review_start(message: types.Message):
    await message.answer("Оцените товар от 1 до 5:")
    await ReviewStates.waiting_for_rating.set()

# Обработка рейтинга
@dp.message_handler(state=ReviewStates.waiting_for_rating)
async def process_rating(message: types.Message, state: FSMContext):
    try:
        rating = int(message.text)
        if rating < 1 or rating > 5:
            raise ValueError
    except ValueError:
        await message.answer("Пожалуйста, введите число от 1 до 5.")
        return

    await state.update_data(rating=rating)
    await message.answer("Напишите комментарий (или отправьте пустое сообщение для пропуска):")
    await ReviewStates.waiting_for_comment.set()

# Обработка комментария и сохранение отзыва
@dp.message_handler(state=ReviewStates.waiting_for_comment)
async def process_comment(message: types.Message, state: FSMContext):
    user_data = await state.get_data()
    rating = user_data['rating']
    comment = message.text.strip() if message.text else None

    review = Review(
        user_id=message.from_user.id,
        username=message.from_user.username,
        rating=rating,
        comment=comment if comment else None,
    )

    reviews_storage.append(review)
    await message.answer("Спасибо за ваш отзыв!")

    logger.info(f"Новый отзыв: {review.json()}")

    await state.finish()

# Команда для просмотра всех отзывов (только для админа, id подставить)
ADMIN_USER_ID = 123456789

@dp.message_handler(commands=['get_reviews'])
async def get_reviews(message: types.Message):
    if message.from_user.id != ADMIN_USER_ID:
        await message.answer("У вас нет доступа к этой команде.")
        return

    if not reviews_storage:
        await message.answer("Отзывов пока нет.")
        return

    response = "Отзывы пользователей:\n\n"
    for i, review in enumerate(reviews_storage, 1):
        response += f"{i}. @{review.username or 'anonymous'} - Оценка: {review.rating}\n"
        if review.comment:
            response += f"Комментарий: {review.comment}\n"
        response += "\n"
    await message.answer(response)

if __name__ == '__main__':
    executor.start_polling(dp, skip_updates=True)
