# agent_mash/core/base_agent.py

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from agent_mash.core.agent_message import AgentMessage
import asyncio
import logging
from enum import Enum
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

class AgentStatus(Enum):
    STARTING = "starting"
    RUNNING = "running"
    IDLE = "idle"
    BUSY = "busy"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"

class AgentType(Enum):
    LLM = "llm"
    RL = "rl"
    RULE = "rule"
    HYBRID = "hybrid"

@dataclass
class AgentCapability:
    name: str
    version: str
    description: str
    max_concurrent: int = 1
    avg_latency_ms: float = 1000.0

@dataclass
class AgentMetrics:
    total_messages: int = 0
    success_messages: int = 0
    failed_messages: int = 0
    avg_response_time: float = 0.0
    last_activity: Optional[datetime] = None
    cpu_usage: float = 0.0
    memory_usage: float = 0.0

class BaseAgent(ABC):
    """
    Базовый класс для всех агентов в системе AetherNova.
    Определяет единый интерфейс для коммуникации и управления.
    """

    def __init__(self, agent_id: str, agent_type: AgentType, capabilities: List[AgentCapability] = None):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.capabilities = capabilities or []
        self.status = AgentStatus.STOPPED
        self.metrics = AgentMetrics()
        self.config: Dict[str, Any] = {}
        self._running_tasks: Dict[str, asyncio.Task] = {}
        self._message_queue = asyncio.Queue()

    @abstractmethod
    async def initialize(self) -> bool:
        """
        Инициализация агента. Должна быть переопределена в дочерних классах.
        Возвращает True, если инициализация прошла успешно.
        """
        pass

    @abstractmethod
    async def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """
        Обработка входящего сообщения.
        Возвращает ответное сообщение или None.
        """
        pass

    @abstractmethod
    async def shutdown(self) -> bool:
        """
        Корректное завершение работы агента.
        Возвращает True, если завершение прошло успешно.
        """
        pass

    async def start(self) -> bool:
        """Запуск агента"""
        try:
            self.status = AgentStatus.STARTING
            logger.info(f"Starting agent {self.agent_id}")
            
            if await self.initialize():
                self.status = AgentStatus.RUNNING
                # Запуск основного цикла обработки сообщений
                asyncio.create_task(self._message_loop())
                logger.info(f"Agent {self.agent_id} started successfully")
                return True
            else:
                self.status = AgentStatus.ERROR
                logger.error(f"Failed to initialize agent {self.agent_id}")
                return False
        except Exception as e:
            self.status = AgentStatus.ERROR
            logger.error(f"Error starting agent {self.agent_id}: {e}")
            return False

    async def stop(self) -> bool:
        """Остановка агента"""
        try:
            self.status = AgentStatus.STOPPING
            logger.info(f"Stopping agent {self.agent_id}")
            
            # Отмена всех выполняющихся задач
            for task_id, task in self._running_tasks.items():
                if not task.done():
                    task.cancel()
                    logger.debug(f"Cancelled task {task_id} for agent {self.agent_id}")
            
            # Очистка задач
            self._running_tasks.clear()
            
            # Вызов пользовательского метода завершения
            success = await self.shutdown()
            
            self.status = AgentStatus.STOPPED
            logger.info(f"Agent {self.agent_id} stopped")
            return success
        except Exception as e:
            self.status = AgentStatus.ERROR
            logger.error(f"Error stopping agent {self.agent_id}: {e}")
            return False

    async def send_message(self, message: AgentMessage):
        """Отправить сообщение в очередь агента"""
        await self._message_queue.put(message)

    async def _message_loop(self):
        """Основной цикл обработки сообщений"""
        while self.status == AgentStatus.RUNNING:
            try:
                # Получение сообщения с таймаутом
                message = await asyncio.wait_for(self._message_queue.get(), timeout=1.0)
                
                # Проверка на истечение времени жизни
                if message.is_expired():
                    logger.warning(f"Message {message.message_id} expired, skipping")
                    continue
                
                self.status = AgentStatus.BUSY
                self.metrics.total_messages += 1
                
                # Обработка сообщения
                start_time = datetime.now()
                try:
                    response = await self.process_message(message)
                    self.metrics.success_messages += 1
                    
                    # Если есть ответ и указан reply_to, отправляем ответ
                    if response and message.reply_to:
                        # Здесь должна быть логика отправки ответа через AgentBus
                        logger.debug(f"Response ready for {message.reply_to}: {response}")
                        
                except Exception as e:
                    self.metrics.failed_messages += 1
                    logger.error(f"Error processing message {message.message_id}: {e}")
                
                # Обновление метрик
                end_time = datetime.now()
                response_time = (end_time - start_time).total_seconds() * 1000
                self._update_response_time(response_time)
                self.metrics.last_activity = end_time
                
                self.status = AgentStatus.RUNNING
                
            except asyncio.TimeoutError:
                # Нет новых сообщений, переходим в режим ожидания
                if self.status == AgentStatus.RUNNING:
                    self.status = AgentStatus.IDLE
            except Exception as e:
                logger.error(f"Error in message loop for agent {self.agent_id}: {e}")
                self.status = AgentStatus.ERROR
                break

    def _update_response_time(self, new_time: float):
        """Обновление среднего времени ответа"""
        if self.metrics.avg_response_time == 0:
            self.metrics.avg_response_time = new_time
        else:
            # Экспоненциальное сглаживание
            alpha = 0.1
            self.metrics.avg_response_time = (
                alpha * new_time + (1 - alpha) * self.metrics.avg_response_time
            )

    def get_status(self) -> Dict[str, Any]:
        """Получить текущий статус агента"""
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type.value,
            "status": self.status.value,
            "capabilities": [cap.__dict__ for cap in self.capabilities],
            "metrics": {
                "total_messages": self.metrics.total_messages,
                "success_messages": self.metrics.success_messages,
                "failed_messages": self.metrics.failed_messages,
                "success_rate": (self.metrics.success_messages / max(1, self.metrics.total_messages)) * 100,
                "avg_response_time": self.metrics.avg_response_time,
                "last_activity": self.metrics.last_activity.isoformat() if self.metrics.last_activity else None,
                "cpu_usage": self.metrics.cpu_usage,
                "memory_usage": self.metrics.memory_usage
            }
        }

    def supports_task_type(self, task_type: str) -> bool:
        """Проверить, поддерживает ли агент данный тип задач"""
        return any(cap.name == task_type for cap in self.capabilities)

    def add_capability(self, capability: AgentCapability):
        """Добавить новую возможность агента"""
        self.capabilities.append(capability)

    def remove_capability(self, capability_name: str):
        """Удалить возможность агента"""
        self.capabilities = [cap for cap in self.capabilities if cap.name != capability_name]