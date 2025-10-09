#!/usr/bin/env python3
"""
FastAPI приложение для демонстрации AI Core Agent System

Запуск:
    python app.py

Или через uvicorn:
    uvicorn app:app --host 0.0.0.0 --port 8000 --reload
"""

import asyncio
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from contextlib import asynccontextmanager
import logging

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

from backend.ai_core.agents import (
    agent_system,
    router as agent_router,
    dashboard_router,
    config_manager
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Управление жизненным циклом приложения"""
    # Запуск
    try:
        logging.info("Starting AI Core Agent System...")
        await agent_system.initialize()
        logging.info("AI Core Agent System started successfully")
        yield
    finally:
        # Завершение
        logging.info("Shutting down AI Core Agent System...")
        await agent_system.shutdown()
        logging.info("AI Core Agent System shutdown complete")

# Создание FastAPI приложения
app = FastAPI(
    title="AetherNova AI Core Agent System",
    description="""
    🤖 **AI Core Agent System** - Комплексная система искусственного интеллекта для автоматизации разработки
    
    ## Возможности
    
    * **Мета-генералы**: Системный архитектор, эволюционер, страж безопасности
    * **Ролевые агенты**: Архитектор, разработчик, тестировщик, ревьюер
    * **Мониторинг**: Реальное время отслеживания производительности и здоровья
    * **Система очередей**: RabbitMQ/In-Memory для масштабируемого взаимодействия
    * **Политики безопасности**: Контроль доступа и compliance
    * **Веб-дашборд**: Интерактивная панель управления и мониторинга
    
    ## Использование
    
    1. **Отправка задач**: `POST /ai-core/agents/tasks`
    2. **Мониторинг**: `/dashboard` - веб-интерфейс
    3. **Управление агентами**: `GET /ai-core/agents`
    4. **Системный статус**: `GET /ai-core/agents/system/status`
    
    ---
    *Powered by AetherNova Technologies*
    """,
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # В продакшене указать конкретные домены
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Подключение роутеров
app.include_router(agent_router, prefix="/ai-core")
app.include_router(dashboard_router)

@app.get("/", include_in_schema=False)
async def root():
    """Перенаправление на дашборд"""
    return RedirectResponse(url="/dashboard")

@app.get("/health")
async def health_check():
    """Проверка здоровья приложения"""
    try:
        system_status = await agent_system.get_system_status()
        
        return {
            "status": "healthy",
            "timestamp": "2025-10-08T10:00:00Z",
            "version": "1.0.0",
            "system": system_status,
            "environment": config_manager.get_environment()
        }
        
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"System unhealthy: {e}")

@app.get("/info")
async def system_info():
    """Информация о системе"""
    system_config = config_manager.get_system_config()
    
    return {
        "name": system_config.name,
        "version": system_config.version,
        "environment": system_config.environment,
        "features": {
            "metagenerals": ["SystemArchitect", "SystemEvolver", "SystemGuardian"],
            "role_agents": ["ArchitectAgent", "DeveloperAgent", "TesterAgent", "ReviewerAgent"],
            "monitoring": "Real-time performance and health monitoring",
            "message_queue": "RabbitMQ/In-Memory support",
            "dashboard": "Web-based monitoring dashboard",
            "notifications": "Email, Slack, Webhook alerts",
            "policies": "Security and compliance engine"
        },
        "api_endpoints": {
            "agents": "/ai-core/agents",
            "tasks": "/ai-core/agents/tasks", 
            "system_status": "/ai-core/agents/system/status",
            "dashboard": "/dashboard",
            "health": "/health",
            "docs": "/docs"
        }
    }

# Обработчик ошибок
@app.exception_handler(500)
async def internal_server_error(request, exc):
    return {
        "error": "Internal server error",
        "message": "An unexpected error occurred. Please check the logs.",
        "timestamp": "2025-10-08T10:00:00Z"
    }

# Запуск приложения
if __name__ == "__main__":
    # Конфигурация из настроек
    api_config = config_manager.get_api_config()
    
    uvicorn.run(
        "app:app",
        host=api_config.get("host", "0.0.0.0"),
        port=api_config.get("port", 8000),
        reload=config_manager.is_development_mode(),
        log_level="info" if not config_manager.is_development_mode() else "debug",
        access_log=True
    )