from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import sessionmaker
from backend.core.settings import settings

# Создаём асинхронный движок базы данных
engine = create_async_engine(
    settings.database_url,
    echo=settings.db_echo,
    future=True,
)

# Асинхронный sessionmaker для управления сессиями
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    expire_on_commit=False,
    class_=AsyncSession,
)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Асинхронный генератор сессий для зависимости FastAPI.
    Гарантирует создание и закрытие сессии на каждый запрос.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
