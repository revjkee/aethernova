import asyncio
import json
import logging
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
import aio_pika
from aio_pika import Message, DeliveryMode
from aio_pika.abc import AbstractConnection, AbstractChannel, AbstractQueue

from .bus import MessageBus, QueueMetrics
from ..base import Priority

class RabbitMQMessageBus(MessageBus):
    """Реализация системы сообщений с RabbitMQ"""
    
    def __init__(self, connection_url: str = "amqp://guest:guest@localhost:5672/"):
        self.connection_url = connection_url
        self.connection: Optional[AbstractConnection] = None
        self.channel: Optional[AbstractChannel] = None
        self.queues: Dict[str, AbstractQueue] = {}
        self.handlers: Dict[str, List[Callable]] = {}
        self.logger = logging.getLogger(self.__class__.__name__)
        self.is_connected = False
        
    async def connect(self) -> bool:
        """Подключение к RabbitMQ"""
        try:
            self.connection = await aio_pika.connect_robust(self.connection_url)
            self.channel = await self.connection.channel()
            
            # Настройка QoS для справедливого распределения
            await self.channel.set_qos(prefetch_count=1)
            
            self.is_connected = True
            self.logger.info("Connected to RabbitMQ")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to RabbitMQ: {e}")
            self.is_connected = False
            return False
            
    async def disconnect(self) -> None:
        """Отключение от RabbitMQ"""
        try:
            if self.connection and not self.connection.is_closed:
                await self.connection.close()
                
            self.is_connected = False
            self.logger.info("Disconnected from RabbitMQ")
            
        except Exception as e:
            self.logger.error(f"Error disconnecting from RabbitMQ: {e}")
            
    async def _ensure_connected(self) -> bool:
        """Проверка подключения"""
        if not self.is_connected or not self.connection or self.connection.is_closed:
            return await self.connect()
        return True
        
    async def publish(self, queue_name: str, message: Dict[str, Any], priority: Priority = Priority.MEDIUM) -> bool:
        """Публикация сообщения в очередь"""
        try:
            if not await self._ensure_connected():
                return False
                
            # Создание очереди если она не существует
            await self.create_queue(queue_name)
            
            # Подготовка сообщения
            message_body = json.dumps({
                "timestamp": datetime.now().isoformat(),
                "priority": priority.value,
                "data": message
            })
            
            # Создание сообщения RabbitMQ
            rabbit_message = Message(
                message_body.encode(),
                delivery_mode=DeliveryMode.PERSISTENT,  # Сообщение переживет перезапуск
                priority=priority.value,
                timestamp=datetime.now()
            )
            
            # Публикация
            if queue_name in self.queues:
                await self.channel.default_exchange.publish(
                    rabbit_message,
                    routing_key=queue_name
                )
                
                self.logger.info(f"Published message to queue {queue_name}")
                return True
            else:
                self.logger.error(f"Queue {queue_name} not found")
                return False
                
        except Exception as e:
            self.logger.error(f"Error publishing message to {queue_name}: {e}")
            return False
            
    async def subscribe(self, queue_name: str, handler: Callable) -> bool:
        """Подписка на очередь с обработчиком"""
        try:
            if not await self._ensure_connected():
                return False
                
            # Создание очереди если она не существует
            await self.create_queue(queue_name)
            
            if queue_name not in self.handlers:
                self.handlers[queue_name] = []
                
            self.handlers[queue_name].append(handler)
            
            # Настройка потребителя
            if queue_name in self.queues:
                queue = self.queues[queue_name]
                
                async def message_handler(message: aio_pika.abc.AbstractIncomingMessage):
                    async with message.process():
                        try:
                            # Парсинг сообщения
                            body = json.loads(message.body.decode())
                            
                            # Вызов всех обработчиков
                            for handler_func in self.handlers[queue_name]:
                                await handler_func(body)
                                
                        except Exception as e:
                            self.logger.error(f"Error processing message: {e}")
                            raise  # Это отклонит сообщение
                            
                await queue.consume(message_handler)
                self.logger.info(f"Subscribed to queue {queue_name}")
                return True
            else:
                self.logger.error(f"Queue {queue_name} not found")
                return False
                
        except Exception as e:
            self.logger.error(f"Error subscribing to queue {queue_name}: {e}")
            return False
            
    async def consume(self, queue_name: str, max_messages: int = 1) -> List[Dict[str, Any]]:
        """Получение сообщений из очереди"""
        try:
            if not await self._ensure_connected():
                return []
                
            if queue_name not in self.queues:
                await self.create_queue(queue_name)
                
            messages = []
            queue = self.queues[queue_name]
            
            for _ in range(max_messages):
                try:
                    message = await queue.get(timeout=1.0, no_ack=False)
                    if message:
                        body = json.loads(message.body.decode())
                        body["_rabbit_message"] = message  # Для последующего acknowledge
                        messages.append(body)
                    else:
                        break
                        
                except asyncio.TimeoutError:
                    break
                    
            return messages
            
        except Exception as e:
            self.logger.error(f"Error consuming messages from {queue_name}: {e}")
            return []
            
    async def acknowledge(self, queue_name: str, message_id: str) -> bool:
        """Подтверждение обработки сообщения"""
        try:
            # В реальной реализации message_id должен содержать ссылку на RabbitMQ message
            # Для простоты здесь заглушка
            self.logger.info(f"Acknowledged message {message_id} from queue {queue_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error acknowledging message: {e}")
            return False
            
    async def reject(self, queue_name: str, message_id: str, requeue: bool = True) -> bool:
        """Отклонение сообщения"""
        try:
            # В реальной реализации message_id должен содержать ссылку на RabbitMQ message
            # Для простоты здесь заглушка
            self.logger.info(f"Rejected message {message_id} from queue {queue_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error rejecting message: {e}")
            return False
            
    async def get_metrics(self, queue_name: str) -> QueueMetrics:
        """Получение метрик очереди"""
        try:
            if not await self._ensure_connected():
                return self._empty_metrics(queue_name)
                
            if queue_name in self.queues:
                queue = self.queues[queue_name]
                
                # Получение информации об очереди через RabbitMQ Management API
                # Для простоты возвращаем базовые метрики
                return QueueMetrics(
                    queue_name=queue_name,
                    total_messages=0,  # Будет получено через Management API
                    pending_messages=0,
                    processing_messages=0,
                    completed_messages=0,
                    failed_messages=0,
                    avg_processing_time=0.0,
                    throughput_per_minute=0.0
                )
            else:
                return self._empty_metrics(queue_name)
                
        except Exception as e:
            self.logger.error(f"Error getting metrics for {queue_name}: {e}")
            return self._empty_metrics(queue_name)
            
    async def create_queue(self, queue_name: str, durable: bool = True, exclusive: bool = False) -> bool:
        """Создание очереди"""
        try:
            if not await self._ensure_connected():
                return False
                
            if queue_name not in self.queues:
                queue = await self.channel.declare_queue(
                    queue_name,
                    durable=durable,
                    exclusive=exclusive,
                    auto_delete=False,
                    arguments={
                        "x-max-priority": 10  # Поддержка приоритетов
                    }
                )
                
                self.queues[queue_name] = queue
                self.logger.info(f"Created queue {queue_name}")
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating queue {queue_name}: {e}")
            return False
            
    async def delete_queue(self, queue_name: str) -> bool:
        """Удаление очереди"""
        try:
            if not await self._ensure_connected():
                return False
                
            if queue_name in self.queues:
                queue = self.queues[queue_name]
                await queue.delete()
                del self.queues[queue_name]
                
            if queue_name in self.handlers:
                del self.handlers[queue_name]
                
            self.logger.info(f"Deleted queue {queue_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error deleting queue {queue_name}: {e}")
            return False
            
    def _empty_metrics(self, queue_name: str) -> QueueMetrics:
        """Создание пустых метрик"""
        return QueueMetrics(
            queue_name=queue_name,
            total_messages=0,
            pending_messages=0,
            processing_messages=0,
            completed_messages=0,
            failed_messages=0,
            avg_processing_time=0.0,
            throughput_per_minute=0.0
        )