from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from datetime import datetime
import asyncio
import json
import logging

from ..base import Task, Priority

@dataclass 
class QueueMetrics:
    queue_name: str
    total_messages: int
    pending_messages: int
    processing_messages: int
    completed_messages: int
    failed_messages: int
    avg_processing_time: float
    throughput_per_minute: float

class MessageBus(ABC):
    """Абстрактный базовый класс для системы сообщений"""
    
    @abstractmethod
    async def publish(self, queue_name: str, message: Dict[str, Any], priority: Priority = Priority.MEDIUM) -> bool:
        """Публикация сообщения в очередь"""
        pass
    
    @abstractmethod
    async def subscribe(self, queue_name: str, handler: Callable) -> bool:
        """Подписка на очередь с обработчиком"""
        pass
    
    @abstractmethod
    async def consume(self, queue_name: str, max_messages: int = 1) -> List[Dict[str, Any]]:
        """Получение сообщений из очереди"""
        pass
    
    @abstractmethod
    async def acknowledge(self, queue_name: str, message_id: str) -> bool:
        """Подтверждение обработки сообщения"""
        pass
    
    @abstractmethod
    async def reject(self, queue_name: str, message_id: str, requeue: bool = True) -> bool:
        """Отклонение сообщения"""
        pass
    
    @abstractmethod
    async def get_metrics(self, queue_name: str) -> QueueMetrics:
        """Получение метрик очереди"""
        pass
    
    @abstractmethod
    async def create_queue(self, queue_name: str, durable: bool = True, exclusive: bool = False) -> bool:
        """Создание очереди"""
        pass
    
    @abstractmethod
    async def delete_queue(self, queue_name: str) -> bool:
        """Удаление очереди"""
        pass

class InMemoryMessageBus(MessageBus):
    """Реализация системы сообщений в памяти для тестирования"""
    
    def __init__(self):
        self.queues: Dict[str, List[Dict[str, Any]]] = {}
        self.handlers: Dict[str, List[Callable]] = {}
        self.metrics: Dict[str, QueueMetrics] = {}
        self.message_counter = 0
        self.logger = logging.getLogger(self.__class__.__name__)
        
    async def publish(self, queue_name: str, message: Dict[str, Any], priority: Priority = Priority.MEDIUM) -> bool:
        """Публикация сообщения в очередь"""
        try:
            if queue_name not in self.queues:
                await self.create_queue(queue_name)
                
            self.message_counter += 1
            wrapped_message = {
                "id": f"msg_{self.message_counter}",
                "priority": priority.value,
                "timestamp": datetime.now().isoformat(),
                "data": message,
                "attempts": 0,
                "status": "pending"
            }
            
            # Вставка с учетом приоритета
            queue = self.queues[queue_name]
            inserted = False
            
            for i, existing_msg in enumerate(queue):
                if Priority(existing_msg["priority"]).value < priority.value:
                    queue.insert(i, wrapped_message)
                    inserted = True
                    break
                    
            if not inserted:
                queue.append(wrapped_message)
                
            # Обновление метрик
            await self._update_metrics(queue_name)
            
            # Уведомление подписчиков
            if queue_name in self.handlers:
                for handler in self.handlers[queue_name]:
                    asyncio.create_task(handler(wrapped_message))
                    
            self.logger.info(f"Published message to queue {queue_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error publishing message: {e}")
            return False
            
    async def subscribe(self, queue_name: str, handler: Callable) -> bool:
        """Подписка на очередь с обработчиком"""
        try:
            if queue_name not in self.handlers:
                self.handlers[queue_name] = []
                
            self.handlers[queue_name].append(handler)
            self.logger.info(f"Subscribed to queue {queue_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error subscribing to queue: {e}")
            return False
            
    async def consume(self, queue_name: str, max_messages: int = 1) -> List[Dict[str, Any]]:
        """Получение сообщений из очереди"""
        try:
            if queue_name not in self.queues:
                return []
                
            queue = self.queues[queue_name]
            messages = []
            
            for _ in range(min(max_messages, len(queue))):
                if queue:
                    message = queue.pop(0)
                    message["status"] = "processing"
                    message["attempts"] += 1
                    messages.append(message)
                    
            await self._update_metrics(queue_name)
            return messages
            
        except Exception as e:
            self.logger.error(f"Error consuming messages: {e}")
            return []
            
    async def acknowledge(self, queue_name: str, message_id: str) -> bool:
        """Подтверждение обработки сообщения"""
        try:
            # В реальной реализации здесь было бы удаление из временного хранилища
            self.logger.info(f"Acknowledged message {message_id} from queue {queue_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error acknowledging message: {e}")
            return False
            
    async def reject(self, queue_name: str, message_id: str, requeue: bool = True) -> bool:
        """Отклонение сообщения"""
        try:
            if requeue and queue_name in self.queues:
                # Вернуть сообщение в очередь (с увеличенным счетчиком попыток)
                pass
                
            self.logger.info(f"Rejected message {message_id} from queue {queue_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error rejecting message: {e}")
            return False
            
    async def get_metrics(self, queue_name: str) -> QueueMetrics:
        """Получение метрик очереди"""
        if queue_name not in self.metrics:
            await self._update_metrics(queue_name)
            
        return self.metrics.get(queue_name, QueueMetrics(
            queue_name=queue_name,
            total_messages=0,
            pending_messages=0,
            processing_messages=0,
            completed_messages=0,
            failed_messages=0,
            avg_processing_time=0.0,
            throughput_per_minute=0.0
        ))
        
    async def create_queue(self, queue_name: str, durable: bool = True, exclusive: bool = False) -> bool:
        """Создание очереди"""
        try:
            if queue_name not in self.queues:
                self.queues[queue_name] = []
                await self._update_metrics(queue_name)
                self.logger.info(f"Created queue {queue_name}")
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating queue: {e}")
            return False
            
    async def delete_queue(self, queue_name: str) -> bool:
        """Удаление очереди"""
        try:
            if queue_name in self.queues:
                del self.queues[queue_name]
                
            if queue_name in self.handlers:
                del self.handlers[queue_name]
                
            if queue_name in self.metrics:
                del self.metrics[queue_name]
                
            self.logger.info(f"Deleted queue {queue_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error deleting queue: {e}")
            return False
            
    async def _update_metrics(self, queue_name: str):
        """Обновление метрик очереди"""
        if queue_name not in self.queues:
            return
            
        queue = self.queues[queue_name]
        pending = len([m for m in queue if m.get("status") == "pending"])
        processing = len([m for m in queue if m.get("status") == "processing"])
        
        self.metrics[queue_name] = QueueMetrics(
            queue_name=queue_name,
            total_messages=len(queue),
            pending_messages=pending,
            processing_messages=processing,
            completed_messages=0,  # Будет обновлено в реальной реализации
            failed_messages=0,     # Будет обновлено в реальной реализации
            avg_processing_time=0.0,  # Будет вычислено в реальной реализации
            throughput_per_minute=0.0  # Будет вычислено в реальной реализации
        )

# Глобальный экземпляр шины сообщений
message_bus = InMemoryMessageBus()