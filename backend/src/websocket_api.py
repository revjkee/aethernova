# backend/src/websocket_api.py
"""
WebSocket API для real-time обновлений системы агентов
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Set
from uuid import uuid4

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Модели для WebSocket сообщений
class WSMessage(BaseModel):
    """Базовая модель WebSocket сообщения"""
    type: str
    data: Dict
    timestamp: str = None
    
    def __init__(self, **data):
        if 'timestamp' not in data or data['timestamp'] is None:
            data['timestamp'] = datetime.now(timezone.utc).isoformat()
        super().__init__(**data)

class AgentStatusUpdate(BaseModel):
    """Обновление статуса агента"""
    agent_id: str
    status: str
    message: str = ""

class TaskUpdate(BaseModel):
    """Обновление статуса задачи"""
    task_id: str
    agent_id: str
    status: str
    progress: float = 0.0
    result: Dict = {}

class SystemMetrics(BaseModel):
    """Системные метрики"""
    active_agents: int
    total_tasks: int
    completed_tasks: int
    failed_tasks: int
    cpu_usage: float
    memory_usage: float

# Менеджер WebSocket соединений
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.subscriptions: Dict[str, Set[str]] = {
            "agent_updates": set(),
            "task_updates": set(),
            "system_metrics": set(),
            "all": set()
        }

    async def connect(self, websocket: WebSocket, client_id: str):
        """Подключение нового клиента"""
        await websocket.accept()
        self.active_connections[client_id] = websocket
        logger.info(f"WebSocket client {client_id} connected")

    def disconnect(self, client_id: str):
        """Отключение клиента"""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
            
        # Удаляем из всех подписок
        for topic_subscribers in self.subscriptions.values():
            topic_subscribers.discard(client_id)
            
        logger.info(f"WebSocket client {client_id} disconnected")

    def subscribe(self, client_id: str, topic: str):
        """Подписка на топик"""
        if topic in self.subscriptions:
            self.subscriptions[topic].add(client_id)
            logger.info(f"Client {client_id} subscribed to {topic}")

    def unsubscribe(self, client_id: str, topic: str):
        """Отписка от топика"""
        if topic in self.subscriptions:
            self.subscriptions[topic].discard(client_id)
            logger.info(f"Client {client_id} unsubscribed from {topic}")

    async def send_personal_message(self, message: str, client_id: str):
        """Отправка личного сообщения"""
        if client_id in self.active_connections:
            websocket = self.active_connections[client_id]
            try:
                await websocket.send_text(message)
            except Exception as e:
                logger.error(f"Error sending message to {client_id}: {e}")
                self.disconnect(client_id)

    async def broadcast_to_topic(self, message: WSMessage, topic: str):
        """Отправка сообщения всем подписчикам топика"""
        subscribers = self.subscriptions.get(topic, set()) | self.subscriptions.get("all", set())
        
        if subscribers:
            message_text = message.model_dump_json()
            disconnected_clients = []
            
            for client_id in subscribers:
                if client_id in self.active_connections:
                    websocket = self.active_connections[client_id]
                    try:
                        await websocket.send_text(message_text)
                    except Exception as e:
                        logger.error(f"Error broadcasting to {client_id}: {e}")
                        disconnected_clients.append(client_id)
            
            # Удаляем отключенных клиентов
            for client_id in disconnected_clients:
                self.disconnect(client_id)

    async def broadcast_agent_update(self, agent_update: AgentStatusUpdate):
        """Отправка обновления статуса агента"""
        message = WSMessage(
            type="agent_status",
            data=agent_update.model_dump()
        )
        await self.broadcast_to_topic(message, "agent_updates")

    async def broadcast_task_update(self, task_update: TaskUpdate):
        """Отправка обновления статуса задачи"""
        message = WSMessage(
            type="task_update", 
            data=task_update.model_dump()
        )
        await self.broadcast_to_topic(message, "task_updates")

    async def broadcast_system_metrics(self, metrics: SystemMetrics):
        """Отправка системных метрик"""
        message = WSMessage(
            type="system_metrics",
            data=metrics.model_dump()
        )
        await self.broadcast_to_topic(message, "system_metrics")

# Глобальный менеджер соединений
manager = ConnectionManager()

# Router для WebSocket
router = APIRouter(prefix="/ws", tags=["websocket"])

@router.websocket("/agents")
async def websocket_endpoint(websocket: WebSocket):
    """Основной WebSocket endpoint для real-time обновлений"""
    client_id = str(uuid4())
    
    await manager.connect(websocket, client_id)
    
    try:
        # Отправляем приветственное сообщение
        welcome_message = WSMessage(
            type="connection_established",
            data={
                "client_id": client_id,
                "available_topics": list(manager.subscriptions.keys()),
                "message": "WebSocket connection established"
            }
        )
        await websocket.send_text(welcome_message.model_dump_json())
        
        # Слушаем входящие сообщения
        while True:
            data = await websocket.receive_text()
            
            try:
                message_data = json.loads(data)
                await handle_client_message(client_id, message_data)
            except json.JSONDecodeError:
                error_message = WSMessage(
                    type="error",
                    data={"message": "Invalid JSON format"}
                )
                await websocket.send_text(error_message.model_dump_json())
                
    except WebSocketDisconnect:
        manager.disconnect(client_id)
    except Exception as e:
        logger.error(f"WebSocket error for client {client_id}: {e}")
        manager.disconnect(client_id)

async def handle_client_message(client_id: str, message_data: Dict):
    """Обработка сообщений от клиента"""
    message_type = message_data.get("type")
    
    if message_type == "subscribe":
        topic = message_data.get("topic")
        if topic:
            manager.subscribe(client_id, topic)
            response = WSMessage(
                type="subscription_confirmed",
                data={"topic": topic, "status": "subscribed"}
            )
            await manager.send_personal_message(response.model_dump_json(), client_id)
    
    elif message_type == "unsubscribe":
        topic = message_data.get("topic")
        if topic:
            manager.unsubscribe(client_id, topic)
            response = WSMessage(
                type="subscription_confirmed",
                data={"topic": topic, "status": "unsubscribed"}
            )
            await manager.send_personal_message(response.model_dump_json(), client_id)
    
    elif message_type == "ping":
        pong_message = WSMessage(
            type="pong",
            data={"timestamp": datetime.now(timezone.utc).isoformat()}
        )
        await manager.send_personal_message(pong_message.model_dump_json(), client_id)
    
    else:
        error_message = WSMessage(
            type="error", 
            data={"message": f"Unknown message type: {message_type}"}
        )
        await manager.send_personal_message(error_message.model_dump_json(), client_id)

# Функции для отправки обновлений из других частей приложения
async def notify_agent_status_change(agent_id: str, status: str, message: str = ""):
    """Уведомление об изменении статуса агента"""
    update = AgentStatusUpdate(
        agent_id=agent_id,
        status=status, 
        message=message
    )
    await manager.broadcast_agent_update(update)

async def notify_task_update(task_id: str, agent_id: str, status: str, progress: float = 0.0, result: Dict = {}):
    """Уведомление об обновлении задачи"""
    update = TaskUpdate(
        task_id=task_id,
        agent_id=agent_id,
        status=status,
        progress=progress,
        result=result
    )
    await manager.broadcast_task_update(update)

async def broadcast_system_metrics():
    """Отправка системных метрик"""
    # Здесь должна быть логика получения реальных метрик
    metrics = SystemMetrics(
        active_agents=4,
        total_tasks=25,
        completed_tasks=20,
        failed_tasks=2,
        cpu_usage=45.2,
        memory_usage=1024.5
    )
    await manager.broadcast_system_metrics(metrics)

# Задача для периодической отправки системных метрик
async def metrics_broadcaster():
    """Фоновая задача для отправки метрик каждые 30 секунд"""
    while True:
        try:
            await broadcast_system_metrics()
            await asyncio.sleep(30)
        except Exception as e:
            logger.error(f"Error broadcasting metrics: {e}")
            await asyncio.sleep(60)  # Увеличиваем интервал при ошибке

# Запуск фоновой задачи
asyncio.create_task(metrics_broadcaster())