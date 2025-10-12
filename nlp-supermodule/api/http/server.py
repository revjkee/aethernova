"""
AetherNova NLP Supermodule - HTTP API Server
FastAPI сервер для REST API доступа к NLP задачам
"""

import logging
import asyncio
from typing import List, Optional, Dict, Any
from datetime import datetime
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
import uvicorn

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("nlp-http")

# ============================================================================
# Pydantic Models
# ============================================================================

class SentimentRequest(BaseModel):
    """Запрос на анализ тональности"""
    text: str = Field(..., min_length=1, description="Текст для анализа")
    include_emotions: bool = Field(False, description="Включить анализ эмоций")
    include_aspects: bool = Field(False, description="Включить aspect-based анализ")

class NERRequest(BaseModel):
    """Запрос на распознавание сущностей"""
    text: str = Field(..., min_length=1, description="Текст для анализа")
    min_confidence: float = Field(0.5, ge=0.0, le=1.0, description="Минимальная уверенность")
    normalize: bool = Field(True, description="Нормализовать сущности")
    group_entities: bool = Field(False, description="Группировать связанные сущности")

class GenerationRequest(BaseModel):
    """Запрос на генерацию текста"""
    prompt: str = Field(..., min_length=1, description="Начальный текст")
    max_length: int = Field(100, ge=10, le=1000, description="Максимальная длина")
    temperature: float = Field(0.7, ge=0.1, le=2.0, description="Температура генерации")
    num_return_sequences: int = Field(1, ge=1, le=5, description="Количество вариантов")
    generation_mode: str = Field("greedy", description="Режим генерации")
    
    @validator('generation_mode')
    def validate_mode(cls, v):
        allowed = ["greedy", "beam_search", "sampling", "nucleus"]
        if v not in allowed:
            raise ValueError(f"Mode must be one of {allowed}")
        return v

class SummarizationRequest(BaseModel):
    """Запрос на суммаризацию"""
    text: str = Field(..., min_length=10, description="Текст для суммаризации")
    summary_length: str = Field("medium", description="Длина резюме: short/medium/long")
    summarization_type: str = Field("abstractive", description="Тип: abstractive/extractive")
    
    @validator('summary_length')
    def validate_length(cls, v):
        allowed = ["short", "medium", "long"]
        if v not in allowed:
            raise ValueError(f"Length must be one of {allowed}")
        return v
    
    @validator('summarization_type')
    def validate_type(cls, v):
        allowed = ["abstractive", "extractive"]
        if v not in allowed:
            raise ValueError(f"Type must be one of {allowed}")
        return v

class BatchSentimentRequest(BaseModel):
    """Пакетный запрос на анализ тональности"""
    texts: List[str] = Field(..., min_items=1, max_items=100, description="Список текстов")
    include_emotions: bool = Field(False, description="Включить анализ эмоций")

class BatchNERRequest(BaseModel):
    """Пакетный запрос на NER"""
    texts: List[str] = Field(..., min_items=1, max_items=100, description="Список текстов")
    min_confidence: float = Field(0.5, ge=0.0, le=1.0, description="Минимальная уверенность")

class BatchSummarizationRequest(BaseModel):
    """Пакетный запрос на суммаризацию"""
    texts: List[str] = Field(..., min_items=1, max_items=50, description="Список текстов")
    summary_length: str = Field("medium", description="Длина резюме")

# ============================================================================
# FastAPI App
# ============================================================================

app = FastAPI(
    title="AetherNova NLP Supermodule API",
    description="Production-grade NLP API для анализа, генерации и обработки текста",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # В продакшене указать конкретные домены
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# Health & Info Endpoints
# ============================================================================

@app.get("/")
async def root():
    """Корневой эндпоинт с информацией об API"""
    return {
        "status": "ok",
        "service": "AetherNova NLP Supermodule",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat(),
        "endpoints": {
            "docs": "/docs",
            "health": "/health",
            "sentiment": "/sentiment",
            "ner": "/ner",
            "generate": "/generate",
            "summarize": "/summarize",
            "batch": {
                "sentiment": "/batch/sentiment",
                "ner": "/batch/ner",
                "summarize": "/batch/summarize"
            },
            "websocket": "/ws/{client_id}"
        }
    }

@app.get("/health")
async def health_check():
    """Health check для мониторинга"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "services": {
            "sentiment_analysis": "operational",
            "entity_recognition": "operational",
            "text_generation": "operational",
            "summarization": "operational"
        }
    }

# ============================================================================
# NLP Task Endpoints
# ============================================================================

@app.post("/sentiment")
async def analyze_sentiment(request: SentimentRequest):
    """
    Анализ тональности текста
    
    Returns:
        - sentiment: positive/negative/neutral
        - confidence: уверенность модели (0-1)
        - emotions: словарь эмоций (если включено)
        - aspects: aspect-based анализ (если включено)
    """
    try:
        from nlp.tasks.nlu.sentiment_analyzer import (
            SentimentAnalyzer, 
            SentimentConfig
        )
        
        config = SentimentConfig(
            include_emotions=request.include_emotions,
            include_aspects=request.include_aspects
        )
        
        analyzer = SentimentAnalyzer(use_gpu=False)
        result = await analyzer.analyze(text=request.text, config=config)
        
        return result.to_dict()
        
    except Exception as e:
        logger.error(f"Sentiment analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/ner")
async def recognize_entities(request: NERRequest):
    """
    Распознавание именованных сущностей (NER)
    
    Returns:
        - entities: список распознанных сущностей
        - entity_count: количество сущностей
        - entity_types: типы найденных сущностей
    """
    try:
        from nlp.tasks.nlu.entity_recognizer import (
            EntityRecognizer,
            NERConfig
        )
        
        config = NERConfig(
            min_confidence=request.min_confidence,
            normalize=request.normalize,
            group_entities=request.group_entities
        )
        
        recognizer = EntityRecognizer(use_gpu=False)
        result = await recognizer.recognize(text=request.text, config=config)
        
        return result.to_dict()
        
    except Exception as e:
        logger.error(f"NER error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/generate")
async def generate_text(request: GenerationRequest):
    """
    Генерация текста на основе промпта
    
    Returns:
        - prompt: исходный промпт
        - generated_texts: список сгенерированных текстов
        - generation_config: использованная конфигурация
    """
    try:
        from nlp.tasks.nlg.text_generator import (
            TextGenerator,
            GenerationConfig,
            GenerationMode
        )
        
        mode = GenerationMode[request.generation_mode.upper()]
        
        config = GenerationConfig(
            max_length=request.max_length,
            temperature=request.temperature,
            num_return_sequences=request.num_return_sequences,
            generation_mode=mode
        )
        
        generator = TextGenerator(use_gpu=False)
        result = await generator.generate(prompt=request.prompt, config=config)
        
        return result.to_dict()
        
    except Exception as e:
        logger.error(f"Generation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/summarize")
async def summarize_text(request: SummarizationRequest):
    """
    Суммаризация текста
    
    Returns:
        - summary: резюме текста
        - original_length: длина исходного текста
        - summary_length: длина резюме
        - compression_ratio: степень сжатия
    """
    try:
        from nlp.tasks.summarization.summarizer import (
            TextSummarizer,
            SummarizationConfig,
            SummarizationType,
            SummaryLength
        )
        
        summary_type = SummarizationType[request.summarization_type.upper()]
        length = SummaryLength[request.summary_length.upper()]
        
        config = SummarizationConfig(
            summarization_type=summary_type,
            summary_length=length
        )
        
        summarizer = TextSummarizer(model_name="bart-cnn", use_gpu=False)
        result = await summarizer.summarize(text=request.text, config=config)
        
        return result.to_dict()
        
    except Exception as e:
        logger.error(f"Summarization error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# Batch Endpoints
# ============================================================================

@app.post("/batch/sentiment")
async def batch_sentiment(request: BatchSentimentRequest):
    """
    Пакетный анализ тональности
    
    Returns:
        - count: количество обработанных текстов
        - results: список результатов
        - processing_time: время обработки
    """
    try:
        from nlp.tasks.nlu.sentiment_analyzer import SentimentAnalyzer
        
        start_time = datetime.now()
        analyzer = SentimentAnalyzer(use_gpu=False)
        
        results = await analyzer.batch_analyze(
            texts=request.texts,
            include_emotions=request.include_emotions
        )
        
        processing_time = (datetime.now() - start_time).total_seconds()
        
        return {
            "count": len(results),
            "results": [r.to_dict() for r in results],
            "processing_time": processing_time
        }
        
    except Exception as e:
        logger.error(f"Batch sentiment error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/batch/ner")
async def batch_ner(request: BatchNERRequest):
    """Пакетное распознавание сущностей"""
    try:
        from nlp.tasks.nlu.entity_recognizer import EntityRecognizer
        
        start_time = datetime.now()
        recognizer = EntityRecognizer(use_gpu=False)
        
        results = await recognizer.batch_recognize(
            texts=request.texts,
            min_confidence=request.min_confidence
        )
        
        processing_time = (datetime.now() - start_time).total_seconds()
        
        return {
            "count": len(results),
            "results": [r.to_dict() for r in results],
            "processing_time": processing_time
        }
        
    except Exception as e:
        logger.error(f"Batch NER error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/batch/summarize")
async def batch_summarize(request: BatchSummarizationRequest):
    """Пакетная суммаризация"""
    try:
        from nlp.tasks.summarization.summarizer import TextSummarizer, SummaryLength
        
        start_time = datetime.now()
        summarizer = TextSummarizer(model_name="bart-cnn", use_gpu=False)
        
        length = SummaryLength[request.summary_length.upper()]
        
        results = await summarizer.batch_summarize(
            texts=request.texts,
            summary_length=length
        )
        
        processing_time = (datetime.now() - start_time).total_seconds()
        
        return {
            "count": len(results),
            "results": [r.to_dict() for r in results],
            "processing_time": processing_time
        }
        
    except Exception as e:
        logger.error(f"Batch summarization error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# WebSocket Integration
# ============================================================================

from fastapi import WebSocket, WebSocketDisconnect

# Импорт WebSocket компонентов
try:
    from api.ws.server import manager, handle_message
except ImportError:
    logger.warning("WebSocket server not available")
    manager = None
    handle_message = None

@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """
    WebSocket эндпоинт для real-time NLP обработки
    
    Поддерживаемые задачи:
    - sentiment: анализ тональности
    - ner: распознавание сущностей
    - generation: генерация текста
    - summarize: суммаризация
    - batch: пакетная обработка
    """
    if manager is None:
        await websocket.close(code=1011, reason="WebSocket не доступен")
        return
    
    await manager.connect(websocket, client_id)
    
    try:
        # Отправка приветственного сообщения
        await manager.send_message(client_id, {
            "type": "welcome",
            "client_id": client_id,
            "timestamp": datetime.now().isoformat(),
            "available_tasks": ["sentiment", "ner", "generation", "summarize", "batch", "ping"]
        })
        
        # Основной цикл обработки сообщений
        while True:
            data = await websocket.receive_json()
            await handle_message(websocket, client_id, data)
            
    except WebSocketDisconnect:
        manager.disconnect(client_id)
        logger.info(f"Client {client_id} disconnected")
    except Exception as e:
        logger.error(f"WebSocket error for {client_id}: {e}")
        manager.disconnect(client_id)

# ============================================================================
# Exception Handlers
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Обработчик HTTP исключений"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": datetime.now().isoformat()
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Обработчик общих исключений"""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": str(exc),
            "timestamp": datetime.now().isoformat()
        }
    )

# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
