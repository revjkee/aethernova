from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import func
from datetime import datetime


class Base(AsyncAttrs, DeclarativeBase):
    """
    Общий базовый класс для всех моделей SQLAlchemy.
    Добавляет стандартные поля: id, created_at, updated_at.
    Использует SQLAlchemy Async ORM.
    """

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
