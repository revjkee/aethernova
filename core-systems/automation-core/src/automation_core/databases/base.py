# SPDX-License-Identifier: Apache-2.0
# automation-core/src/automation_core/databases/base.py
from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path
from typing import AsyncIterator, Optional

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

# Настройки проекта (см. automation_core/config/settings.py)
from automation_core.config.settings import settings

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Declarative Base
# ---------------------------------------------------------------------------
class Base(DeclarativeBase):
    """Единая база для ORM-моделей."""


# ---------------------------------------------------------------------------
# DSN helpers
# ---------------------------------------------------------------------------
def _project_root() -> Path:
    # .../automation-core/src/automation_core/databases/base.py
    return Path(__file__).resolve().parents[3]


def _normalize_postgres_dsn(dsn: str) -> str:
    """
    Приводит Postgres DSN к async-драйверу.
    Вход: postgres://..., postgresql://..., postgresql+psycopg2://...
    Выход: postgresql+asyncpg://...
    """
    dsn = dsn.strip()
    if dsn.startswith("postgres://"):
        dsn = "postgresql://" + dsn[len("postgres://") :]
    if dsn.startswith("postgresql+psycopg2://"):
        dsn = "postgresql://" + dsn[len("postgresql+psycopg2://") :]
    if not dsn.startswith("postgresql+asyncpg://"):
        dsn = dsn.replace("postgresql://", "postgresql+asyncpg://", 1)
    return dsn


def _build_sqlite_url(sqlite_path: Path) -> str:
    # Абсолютный путь для стабильной работы aiosqlite
    ap = sqlite_path if sqlite_path.is_absolute() else (_project_root() / sqlite_path).resolve()
    return f"sqlite+aiosqlite:///{ap.as_posix()}"


def _resolve_database_url() -> str:
    """
    Порядок выбора:
    1) settings.db.postgres_dsn (нормализуем под asyncpg)
    2) settings.db.sqlite_path (aiosqlite)
    """
    if settings.db.postgres_dsn:
        return _normalize_postgres_dsn(settings.db.postgres_dsn)
    sqlite_path = settings.db.sqlite_path or Path("automation.db")
    return _build_sqlite_url(sqlite_path)


# ---------------------------------------------------------------------------
# Engine / Session factory (singletons)
# ---------------------------------------------------------------------------
@lru_cache(maxsize=1)
def get_engine() -> AsyncEngine:
    """
    Создаёт и кеширует AsyncEngine с безопасными дефолтами.
    Параметры берутся из settings.db.*.
    """
    url = _resolve_database_url()
    echo = bool(settings.db.echo_sql)

    engine_kwargs: dict = {
        "echo": echo,
        "pool_pre_ping": True,  # автоматическое восстановление "stale" соединений
    }

    is_pg = url.startswith("postgresql+asyncpg://")
    if is_pg:
        # Пул соединений для нагруженных сервисов
        engine_kwargs.update(
            {
                "pool_size": max(1, settings.db.pool_min_size),
                "max_overflow": max(0, settings.db.pool_max_size - settings.db.pool_min_size),
                "pool_timeout": settings.db.pool_timeout_s,
                "isolation_level": "READ COMMITTED",
            }
        )
        # Для SQLite вышеуказанные параметры игнорируются драйвером и не вредят.

    engine = create_async_engine(url, **engine_kwargs)
    log.info(
        "DB engine initialized",
        extra={"scheme": url.split("://", 1)[0], "echo": echo, "is_pg": is_pg},
    )
    return engine


@lru_cache(maxsize=1)
def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """
    Фабрика сессий: expire_on_commit=False для удобного чтения после commit.
    """
    return async_sessionmaker(
        bind=get_engine(),
        expire_on_commit=False,
        autoflush=False,
        class_=AsyncSession,
    )


# ---------------------------------------------------------------------------
# Context managers
# ---------------------------------------------------------------------------
@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """
    Контекст жизненного цикла сессии БЕЗ автотранзакции.
    Подходит для readonly и составных сценариев.
    """
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
        finally:
            await session.close()


@asynccontextmanager
async def transaction_scope() -> AsyncIterator[AsyncSession]:
    """
    Контекст жизненного цикла сессии С автотранзакцией.
    Любая ошибка → rollback, иначе commit.
    """
    factory = get_session_factory()
    async with factory() as session:
        try:
            async with session.begin():
                yield session
        except Exception:
            # SQLAlchemy откатывает сам, но логируем и гарантируем корректное завершение.
            try:
                await session.rollback()
            except Exception:
                pass
            log.exception("DB transaction rollback due to exception")
            raise
        finally:
            await session.close()


# ---------------------------------------------------------------------------
# Health-check / schema utilities
# ---------------------------------------------------------------------------
async def health_check(timeout_s: float = 5.0) -> bool:
    """
    Простой ping базы: SELECT 1. Возвращает True/False без исключений.
    """
    try:
        async with asyncio.timeout(timeout_s):
            async with session_scope() as s:
                result = await s.execute(text("SELECT 1"))
                _ = result.scalar_one()
        return True
    except Exception as exc:
        log.warning("DB health_check failed: %s", exc.__class__.__name__)
        return False


async def create_schema(drop_existing: bool = False) -> None:
    """
    Создание схемы (create_all) — для тестов/локального окружения.
    В продакшене используйте миграции (Alembic).
    """
    engine = get_engine()
    async with engine.begin() as conn:
        if drop_existing:
            await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    log.info("DB schema created (drop_existing=%s)", drop_existing)


async def drop_schema() -> None:
    """
    Полное удаление схемы — для тестов/чистки локальной БД.
    """
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    log.info("DB schema dropped")


# ---------------------------------------------------------------------------
# Transient error heuristic (опционально полезна верхнему уровню)
# ---------------------------------------------------------------------------
_TRANSIENT_SQLSTATE_PREFIXES = (
    "08",  # connection exception
    "40",  # transaction rollback (serialization failure, deadlock detected)
)


def is_transient_db_error(err: BaseException) -> bool:
    """
    Эвристика распознавания временных ошибок.
    Не выполняет ретраи сама по себе — решает вызывающий код.
    """
    if isinstance(err, OperationalError):
        return True

    if isinstance(err, DBAPIError):
        if err.connection_invalidated:
            return True
        try:
            code = getattr(err.orig, "sqlstate", None) or getattr(err.orig, "pgcode", None)
            if isinstance(code, str) and any(code.startswith(p) for p in _TRANSIENT_SQLSTATE_PREFIXES):
                return True
        except Exception:
            pass
    return False
