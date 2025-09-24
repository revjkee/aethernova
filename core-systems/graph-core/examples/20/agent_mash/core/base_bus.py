# agent-mesh/core/base_bus.py

from abc import ABC, abstractmethod
from typing import Callable
from agent_mesh.core.agent_message import AgentMessage
import logging

logger = logging.getLogger("BaseBus")


class BaseAgentBus(ABC):
    """
    Абстрактный базовый класс для всех транспортов сообщений.
    Все реализации (Redis, Kafka, ZeroMQ, gRPC и т.д.) должны наследоваться от него.
    """

    def __init__(self, config: dict):
        """
        Общая инициализация транспорта.
        """
        self.config = config

    @abstractmethod
    def send(self, message: AgentMessage, target_agent_id: str):
        """
        Отправка сообщения указанному агенту.
        """
        raise NotImplementedError("send() must be implemented by subclass")

    @abstractmethod
    def subscribe(self, agent_id: str, callback: Callable[[AgentMessage], None]):
        """
        Подписка на сообщения, адресованные данному агенту.
        """
        raise NotImplementedError("subscribe() must be implemented by subclass")

    def close(self):
        """
        Очистка или закрытие соединения (по умолчанию — noop).
        """
        logger.info(f"{self.__class__.__name__} closed (noop)")
