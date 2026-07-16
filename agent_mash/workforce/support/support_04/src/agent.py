import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from agent_mash.core.base_agent import BaseAgent, AgentType, AgentCapability, AgentStatus
from agent_mash.core.agent_message import AgentMessage
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)

class Support04(BaseAgent):
    def __init__(self, name="Support04"):
        capabilities = [
            AgentCapability("general_task", "1.0", "Общие задачи агента"),
            AgentCapability("data_processing", "1.0", "Обработка данных"),
            AgentCapability("communication", "1.0", "Коммуникация с другими агентами")
        ]
        super().__init__(name, AgentType.SUPPORT, capabilities)
        self.name = name
        self.tools = []

    async def initialize(self) -> bool:
        """Инициализация агента"""
        try:
            logger.info(f"[{self.name}] Инициализация агента {self.name}")
            
            self.tools = ["basic_tools", "communication_tools"]
            self.config = {
                "max_tasks": 10,
                "timeout": 30,
                "retry_count": 3
            }
            
            logger.info(f"[{self.name}] Инициализация завершена успешно")
            return True
        except Exception as e:
            logger.error(f"[{self.name}] Ошибка инициализации: {e}")
            return False

    async def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Обработка сообщений"""
        try:
            task_type = message.task_type
            payload = message.payload
            
            logger.info(f"[{self.name}] Обрабатываю задачу: {task_type}")
            
            # Базовая обработка
            result = {
                "status": "completed",
                "message": f"Задача {task_type} выполнена агентом {self.name}",
                "agent": self.name,
                "processed_data": payload
            }
            
            # Создание ответного сообщения
            response = AgentMessage(
                sender=self.name,
                recipient=message.sender,
                task_type=f"{task_type}_response",
                payload=result
            )
            
            return response
            
        except Exception as e:
            logger.error(f"[{self.name}] Ошибка обработки сообщения: {e}")
            return None

    async def shutdown(self) -> bool:
        """Завершение работы агента"""
        logger.info(f"[{self.name}] Завершение работы агента")
        return True
