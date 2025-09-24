import logging
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import NullPool
from backend.core.settings import settings
from contextlib import asynccontextmanager

logger = logging.getLogger("database")

# Асинхронный движок SQLAlchemy с NullPool (без пула для SQLite)
engine = create_async_engine(
    settings.database_url,
    echo=False,
    poolclass=NullPool,
)

# Фабрика сессий
SessionLocal = async_sessionmaker(
    bind=engine,
    expire_on_commit=False,
    class_=AsyncSession,
)

@asynccontextmanager
async def get_session() -> AsyncSession:
    """
    Контекстный менеджер для получения сессии с базой.
    Используется в Depends FastAPI и в сервисах.
    """
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except SQLAlchemyError as e:
            await session.rollback()
            logger.error(f"Database session rollback because of error: {e}")
            raise
        finally:
            await session.close()

async def init_db():
    """
    Инициализация БД (если нужно, например, миграции).
    В SQLAlchemy обычно миграции делаются Alembic, поэтому здесь пусто.
    """
    logger.info("Database initialization (Alembic should be used for migrations)")
