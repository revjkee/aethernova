"""
AetherNova NLP Supermodule - WebSocket Server
Real-time streaming NLP processing через WebSocket
"""

import logging
import json
import asyncio
from typing import Dict, Any
from fastapi import WebSocket, WebSocketDisconnect
from datetime import datetime

logger = logging.getLogger("nlp-ws")

class ConnectionManager:
    """Управление WebSocket соединениями"""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.connection_stats: Dict[str, Dict[str, Any]] = {}
    
    async def connect(self, websocket: WebSocket, client_id: str):
        """Подключение клиента"""
        await websocket.accept()
        self.active_connections[client_id] = websocket
        self.connection_stats[client_id] = {
            "connected_at": datetime.now().isoformat(),
            "messages_sent": 0,
            "messages_received": 0
        }
        logger.info(f"Client {client_id} connected. Total: {len(self.active_connections)}")
    
    def disconnect(self, client_id: str):
        """Отключение клиента"""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
            logger.info(f"Client {client_id} disconnected. Total: {len(self.active_connections)}")
    
    async def send_message(self, client_id: str, message: Dict[str, Any]):
        """Отправка сообщения клиенту"""
        if client_id in self.active_connections:
            websocket = self.active_connections[client_id]
            await websocket.send_json(message)
            self.connection_stats[client_id]["messages_sent"] += 1
    
    async def broadcast(self, message: Dict[str, Any]):
        """Рассылка всем подключенным клиентам"""
        for client_id, websocket in self.active_connections.items():
            try:
                await websocket.send_json(message)
                self.connection_stats[client_id]["messages_sent"] += 1
            except Exception as e:
                logger.error(f"Error broadcasting to {client_id}: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Получить статистику соединений"""
        return {
            "total_connections": len(self.active_connections),
            "active_clients": list(self.active_connections.keys()),
            "connection_details": self.connection_stats
        }


manager = ConnectionManager()


async def handle_sentiment_stream(websocket: WebSocket, client_id: str, data: Dict[str, Any]):
    """Потоковый анализ тональности"""
    from nlp.tasks.nlu.sentiment_analyzer import SentimentAnalyzer
    
    text = data.get("text", "")
    if not text:
        await manager.send_message(client_id, {
            "type": "error",
            "message": "Text is required"
        })
        return
    
    # Инициализация анализатора (если нужно)
    analyzer = SentimentAnalyzer(use_gpu=False)
    
    try:
        # Отправка статуса "processing"
        await manager.send_message(client_id, {
            "type": "status",
            "status": "processing",
            "task": "sentiment_analysis"
        })
        
        # Анализ
        result = await analyzer.analyze(
            text=text,
            include_emotions=data.get("include_emotions", False)
        )
        
        # Отправка результата
        await manager.send_message(client_id, {
            "type": "result",
            "task": "sentiment_analysis",
            "data": result.to_dict()
        })
        
    except Exception as e:
        await manager.send_message(client_id, {
            "type": "error",
            "message": str(e)
        })


async def handle_generation_stream(websocket: WebSocket, client_id: str, data: Dict[str, Any]):
    """Потоковая генерация текста (token-by-token)"""
    from nlp.tasks.nlg.text_generator import TextGenerator
    
    prompt = data.get("prompt", "")
    if not prompt:
        await manager.send_message(client_id, {
            "type": "error",
            "message": "Prompt is required"
        })
        return
    
    generator = TextGenerator(model_name="distilgpt2", use_gpu=False)
    
    try:
        await manager.send_message(client_id, {
            "type": "status",
            "status": "generating",
            "task": "text_generation"
        })
        
        # Генерация
        result = await generator.generate(prompt=prompt)
        
        # Симуляция потоковой отправки (по токенам)
        generated_text = result.generated_texts[0]
        words = generated_text.split()
        
        for i, word in enumerate(words):
            await manager.send_message(client_id, {
                "type": "token",
                "task": "text_generation",
                "token": word,
                "position": i,
                "total": len(words)
            })
            await asyncio.sleep(0.05)  # Симуляция задержки
        
        # Финальный результат
        await manager.send_message(client_id, {
            "type": "result",
            "task": "text_generation",
            "data": result.to_dict()
        })
        
    except Exception as e:
        await manager.send_message(client_id, {
            "type": "error",
            "message": str(e)
        })


async def handle_ner_stream(websocket: WebSocket, client_id: str, data: Dict[str, Any]):
    """Потоковое распознавание сущностей"""
    from nlp.tasks.nlu.entity_recognizer import EntityRecognizer
    
    text = data.get("text", "")
    if not text:
        await manager.send_message(client_id, {
            "type": "error",
            "message": "Text is required"
        })
        return
    
    recognizer = EntityRecognizer(use_gpu=False)
    
    try:
        await manager.send_message(client_id, {
            "type": "status",
            "status": "processing",
            "task": "ner"
        })
        
        result = await recognizer.recognize(
            text=text,
            min_confidence=data.get("min_confidence", 0.5)
        )
        
        # Отправка сущностей по одной
        for i, entity in enumerate(result.entities):
            await manager.send_message(client_id, {
                "type": "entity",
                "task": "ner",
                "entity": entity.to_dict(),
                "position": i + 1,
                "total": result.entity_count
            })
            await asyncio.sleep(0.02)
        
        # Финальный результат
        await manager.send_message(client_id, {
            "type": "result",
            "task": "ner",
            "data": result.to_dict()
        })
        
    except Exception as e:
        await manager.send_message(client_id, {
            "type": "error",
            "message": str(e)
        })


# Обработчики задач
TASK_HANDLERS = {
    "sentiment": handle_sentiment_stream,
    "generation": handle_generation_stream,
    "ner": handle_ner_stream
    ,"summarize": handle_summarize_stream
    ,"batch": handle_batch_stream
}

# --- Новый обработчик для суммаризации ---
async def handle_summarize_stream(websocket: WebSocket, client_id: str, data: Dict[str, Any]):
    from nlp.tasks.summarization.summarizer import TextSummarizer, SummarizationType, SummaryLength, SummarizationConfig
    text = data.get("text", "")
    if not text:
        await manager.send_message(client_id, {"type": "error", "message": "Text is required"})
        return
    summary_length = SummaryLength[data.get("summary_length", "medium").upper()]
    summarization_type = SummarizationType[data.get("summarization_type", "abstractive").upper()]
    config = SummarizationConfig(summarization_type=summarization_type, summary_length=summary_length)
    summarizer = TextSummarizer(model_name="bart-cnn", use_gpu=False)
    try:
        await manager.send_message(client_id, {"type": "status", "status": "processing", "task": "summarization"})
        result = await summarizer.summarize(text=text, config=config)
        await manager.send_message(client_id, {"type": "result", "task": "summarization", "data": result.to_dict()})
    except Exception as e:
        await manager.send_message(client_id, {"type": "error", "message": str(e)})

# --- Новый обработчик для batch задач ---
async def handle_batch_stream(websocket: WebSocket, client_id: str, data: Dict[str, Any]):
    task = data.get("subtask")
    texts = data.get("texts", [])
    if not texts or not isinstance(texts, list):
        await manager.send_message(client_id, {"type": "error", "message": "texts (list) required"})
        return
    try:
        if task == "sentiment":
            from nlp.tasks.nlu.sentiment_analyzer import SentimentAnalyzer
            analyzer = SentimentAnalyzer(use_gpu=False)
            results = await analyzer.batch_analyze(texts)
            await manager.send_message(client_id, {"type": "result", "task": "batch_sentiment", "data": [r.to_dict() for r in results]})
        elif task == "ner":
            from nlp.tasks.nlu.entity_recognizer import EntityRecognizer
            recognizer = EntityRecognizer(use_gpu=False)
            results = await recognizer.batch_recognize(texts)
            await manager.send_message(client_id, {"type": "result", "task": "batch_ner", "data": [r.to_dict() for r in results]})
        elif task == "summarize":
            from nlp.tasks.summarization.summarizer import TextSummarizer
            summarizer = TextSummarizer(model_name="bart-cnn", use_gpu=False)
            results = await summarizer.batch_summarize(texts)
            await manager.send_message(client_id, {"type": "result", "task": "batch_summarize", "data": [r.to_dict() for r in results]})
        else:
            await manager.send_message(client_id, {"type": "error", "message": f"Unknown batch subtask: {task}"})
    except Exception as e:
        await manager.send_message(client_id, {"type": "error", "message": str(e)})


async def websocket_endpoint(websocket: WebSocket, client_id: str = None):
    """Основной WebSocket endpoint"""
    
    if not client_id:
        client_id = f"client_{datetime.now().timestamp()}"
    
    await manager.connect(websocket, client_id)
    
    try:
        # Отправка приветствия
        await manager.send_message(client_id, {
            "type": "welcome",
            "message": "Connected to AetherNova NLP WebSocket",
            "client_id": client_id,
            "available_tasks": list(TASK_HANDLERS.keys())
        })
        
        while True:
            # Получение сообщения от клиента
            data = await websocket.receive_json()
            
            manager.connection_stats[client_id]["messages_received"] += 1
            
            task = data.get("task")
            
            if task == "ping":
                await manager.send_message(client_id, {
                    "type": "pong",
                    "timestamp": datetime.now().isoformat()
                })
                continue
            
            if task == "stats":
                await manager.send_message(client_id, {
                    "type": "stats",
                    "data": manager.get_stats()
                })
                continue
            
            # Обработка NLP задач
            if task in TASK_HANDLERS:
                handler = TASK_HANDLERS[task]
                await handler(websocket, client_id, data)
            else:
                await manager.send_message(client_id, {
                    "type": "error",
                    "message": f"Unknown task: {task}. Available: {list(TASK_HANDLERS.keys())}"
                })
    
    except WebSocketDisconnect:
        manager.disconnect(client_id)
        logger.info(f"Client {client_id} disconnected normally")
    
    except Exception as e:
        logger.error(f"WebSocket error for {client_id}: {e}")
        manager.disconnect(client_id)


def setup_websocket_routes(app):
    """Регистрация WebSocket роутов в FastAPI приложении"""
    
    @app.websocket("/ws/{client_id}")
    async def websocket_route(websocket: WebSocket, client_id: str):
        await websocket_endpoint(websocket, client_id)
    
    @app.get("/ws/stats", tags=["WebSocket"])
    async def get_websocket_stats():
        """Получить статистику WebSocket соединений"""
        return manager.get_stats()
