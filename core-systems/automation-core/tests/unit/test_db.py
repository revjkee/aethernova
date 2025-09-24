# SPDX-License-Identifier: MIT
"""
Интеграционные unit-тесты для асинхронного SQLAlchemy слоя.

Ключевые моменты:
- Асинхронный движок: create_async_engine("sqlite+aiosqlite:///:memory:")
- Для in-memory SQLite используется StaticPool и check_same_thread=False, чтобы вся БД
  жила в одном соединении для всех сессий тестов.
- Схема создаётся через run_sync(Base.metadata.create_all) в едином соединении.
- Каждому тесту выдаётся сессия с открытой транзакцией; по завершении — rollback.

Ссылки на специфику:
- Async SQLAlchemy (create_async_engine, AsyncSession, run_sync).  # docs
- Использование StaticPool и check_same_thread=False для :memory:.  # docs
- pytest-asyncio для async тестов.  # docs
"""

from __future__ import annotations

import datetime as dt
import os
import typing as t

import pytest
import pytest_asyncio
from sqlalchemy import DateTime, Integer, String, UniqueConstraint, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool


# ---------------------------
# Declarative schema (тестовая)
# ---------------------------
class Base(DeclarativeBase):
    pass


class Item(Base):
    __tablename__ = "items"
    __table_args__ = (UniqueConstraint("name", name="uq_items_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


# ---------------------------
# Fixtures
# ---------------------------
@pytest_asyncio.fixture(scope="session")
async def engine() -> t.AsyncIterator[AsyncEngine]:
    """
    Глобальный движок для тестов.

    ВАЖНО: Для in-memory SQLite используем StaticPool + check_same_thread=False,
    чтобы все сессии разделяли одно соединение и одну БД в памяти (поведение
    соответствует рекомендациям SQLAlchemy для :memory:).  # docs
    """
    db_url = os.getenv("TEST_DB_URL", "sqlite+aiosqlite:///:memory:")
    kw = {}
    if db_url.startswith("sqlite+aiosqlite://"):
        kw = {
            "poolclass": StaticPool,
            "connect_args": {"check_same_thread": False},
        }

    eng = create_async_engine(db_url, echo=False, future=True, **kw)
    async with eng.begin() as conn:
        # Создаём схему один раз за сессию тестов
        await conn.run_sync(Base.metadata.create_all)  # docs
    try:
        yield eng
    finally:
        await eng.dispose()


@pytest_asyncio.fixture(scope="session")
def session_factory(engine: AsyncEngine) -> sessionmaker[AsyncSession]:
    """
    Фабрика асинхронных сессий.
    """
    return sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)


@pytest_asyncio.fixture()
async def db_session(session_factory: sessionmaker[AsyncSession]) -> t.AsyncIterator[AsyncSession]:
    """
    Сессия с обёрткой в транзакцию на каждый тест.
    По окончании — откат, чтобы состояние БД оставалось чистым.
    """
    async with session_factory() as session:
        trans = await session.begin()
        try:
            yield session
        finally:
            # откат любых изменений теста
            await trans.rollback()


# ---------------------------
# Tests
# ---------------------------
@pytest.mark.asyncio
async def test_engine_connects(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        result = await conn.execute(text("SELECT 1"))
        assert result.scalar_one() == 1


@pytest.mark.asyncio
async def test_crud_roundtrip(db_session: AsyncSession) -> None:
    # Create
    it = Item(name="alpha")
    db_session.add(it)
    await db_session.flush()
    assert it.id is not None

    # Read
    fetched = await db_session.scalar(select(Item).where(Item.name == "alpha"))
    assert fetched is not None and fetched.id == it.id

    # Update
    fetched.name = "alpha-upd"
    await db_session.flush()
    again = await db_session.scalar(select(Item).where(Item.id == it.id))
    assert again is not None and again.name == "alpha-upd"

    # Delete
    await db_session.delete(again)  # type: ignore[arg-type]
    await db_session.flush()
    gone = await db_session.scalar(select(Item).where(Item.id == it.id))
    assert gone is None


@pytest.mark.asyncio
async def test_unique_constraint_violation(db_session: AsyncSession) -> None:
    db_session.add_all([Item(name="uniq"), Item(name="uniq")])
    with pytest.raises(IntegrityError):
        # flush должен поймать нарушение uq_items_name
        await db_session.flush()


@pytest.mark.asyncio
async def test_transaction_rollback(db_session: AsyncSession) -> None:
    # Вставляем и откатываем вручную
    tmp = Item(name="rollback-me")
    db_session.add(tmp)
    await db_session.flush()
    await db_session.rollback()

    # Проверяем, что записи нет
    count = await db_session.scalar(select(func.count()).select_from(Item))
    assert int(count or 0) == 0


@pytest.mark.asyncio
async def test_basic_isolation_between_sessions(session_factory: sessionmaker[AsyncSession]) -> None:
    # Проверяем, что незакоммиченные изменения одной сессии не видны другой
    async with session_factory() as s1, session_factory() as s2:
        await s1.begin()
        s1.add(Item(name="iso"))
        await s1.flush()

        # s2 начинает свою транзакцию и не видит незакоммиченные изменения s1
        cnt_pre = await s2.scalar(select(func.count()).select_from(Item))
        assert int(cnt_pre or 0) == 0

        # Коммитим s1, затем "обнулим" транзакцию s2, чтобы начать новое чтение
        await s1.commit()
        await s2.rollback()

        cnt_post = await s2.scalar(select(func.count()).select_from(Item))
        assert int(cnt_post or 0) == 1
