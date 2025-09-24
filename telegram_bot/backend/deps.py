from typing import AsyncGenerator
from core.db import get_db  # предполагается, что get_db — асинхронный генератор сессий SQLAlchemy AsyncSession
from core.settings import settings
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

# Инициализация движка и sessionmaker (если не сделано в core.db)
# engine = create_async_engine(settings.database_url, echo=True)
# async_session = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Асинхронный генератор сессии SQLAlchemy AsyncSession.
    Используется для управления транзакциями.
    """
    async for session in get_db():
        yield session

async def init_sqlalchemy():
    """
    Инициализация базы данных (если нужно создать таблицы и т.п.)
    Запускается один раз при старте приложения.
    """
    # Импорт Base с моделями
    from backend.models.base import Base
    from core.db import engine  # если engine определён там

    async with engine.begin() as conn:
        # Создаёт все таблицы, описанные в Base.metadata
        await conn.run_sync(Base.metadata.create_all)

async def close_sqlalchemy():
    """
    Закрывает соединение с базой данных (если нужно).
    """
    from core.db import engine
    await engine.dispose()
