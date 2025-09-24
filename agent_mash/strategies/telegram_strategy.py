# agent-mesh/strategies/telegram_strategy.py

from aiogram import Bot, Dispatcher, types
from aiogram.types import Message
from aiogram.utils import executor
from agent_mesh.core.agent_message import AgentMessage
from agent_mesh.agent_bus import AgentBus
from agent_mesh.strategy_router import StrategyRouter
import logging
import os

logger = logging.getLogger("TelegramStrategy")

class TelegramStrategy:
    """
    Входная стратегия Telegram. Принимает сообщения от пользователей,
    конвертирует в AgentMessage и передаёт в стратегический роутер.
    """

    def __init__(self, bot_token: str, agent_bus: AgentBus, router: StrategyRouter):
        self.bot = Bot(token=bot_token)
        self.dp = Dispatcher(self.bot)
        self.bus = agent_bus
        self.router = router
        self.agent_id = "telegram_strategy"

    def register_handlers(self):
        @self.dp.message_handler(commands=["start"])
        async def start_cmd(message: Message):
            await message.reply("Привет! Отправь задачу для AI.")

        @self.dp.message_handler()
        async def handle_text(message: Message):
            user_input = message.text.strip()
            task_type = self._infer_task_type(user_input)

            msg = AgentMessage(
                sender=self.agent_id,
                task_type=task_type,
                payload={
                    "text": user_input,
                    "user_id": message.from_user.id,
                    "username": message.from_user.username
                },
                meta={
                    "origin": "telegram",
                    "chat_id": message.chat.id
                }
            )

            self.router.route(msg)
            await message.reply(f"Задача принята: {task_type}")

    def _infer_task_type(self, text: str) -> str:
        """
        Простая эвристика для определения типа задачи по содержимому
        """
        lowered = text.lower()
        if any(q in lowered for q in ["почему", "как", "что такое"]):
            return "question-answering"
        if any(cmd in lowered for cmd in ["/generate", "напиши", "создай"]):
            return "text-generation"
        return "reasoning"

    def run(self):
        self.register_handlers()
        executor.start_polling(self.dp, skip_updates=True)
