"""
Промышленный фикстурный модуль для тестовой БД (pytest / pytest-asyncio, SQLAlchemy 2.x, async).

Возможности:
- Async SQLAlchemy (ONLY) с поддержкой PostgreSQL (asyncpg) и SQLite (aiosqlite, в т.ч. :memory:).
- Транзакция/сейвпоинт на каждый тест и гарантированный rollback.
- Опциональный прогон Alembic-миграций (если задан ALEMBIC_CONFIG и RUN_MIGRATIONS=true).
- Альтернатива миграциям: авто-инициализация схем из набора metadata-модулей (через METADATA_MODULES).
- Удобные фабрики sessionmaker/engine и интеграционные хелперы для FastAPI.

Переменные окружения:
- TEST_DATABASE_URL    — URL тестовой БД (по умолчанию: sqlite+aiosqlite:///:memory:)
- RUN_MIGRATIONS       — "true"/"1" для прогона Alembic миграций вместо create_all/drop_all.
- ALEMBIC_CONFIG       — путь до alembic.ini (если нужны миграции).
- METADATA_MODULES     — через запятую: полные пути модулей, где лежат SQLAlchemy MetaData (переменные Base/metadata).
                          Пример: "app.models,app.auth.models"

Зависимости:
- pytest
- pytest-asyncio
- SQLAlchemy >= 2.0
- asyncpg (для PostgreSQL) / aiosqlite (для SQLite)
- alembic (опционально, если RUN_MIGRATIONS=true)

Примечание:
- Модуль не утверждает конкретные пути ваших моделей; укажите их через METADATA_MODULES
  либо подключите Alembic.
"""

from __future__ import annotations

import asyncio
import importlib
import logging
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncIterator, Iterable, Optional

import pytest
import pytest_asyncio
from sqlalchemy import event
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

# --- Логирование ----------------------------------------------------------------

logger = logging.getLogger("tests.fixtures.db")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)


# --- Конфигурация ----------------------------------------------------------------

DEFAULT_TEST_DB_URL = "sqlite+aiosqlite:///:memory:"

def _env_bool(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "y"}


@dataclass(frozen=True)
class DBConfig:
    url: str
    run_migrations: bool
    alembic_config: Optional[str]
    metadata_modules: tuple[str, ...]


def load_db_config() -> DBConfig:
    url = os.getenv("TEST_DATABASE_URL", DEFAULT_TEST_DB_URL).strip()
    run_migrations = _env_bool("RUN_MIGRATIONS", False)
    alembic_config = os.getenv("ALEMBIC_CONFIG")
    modules = tuple(
        m.strip()
        for m in os.getenv("METADATA_MODULES", "").split(",")
        if m.strip()
    )
    logger.info(
        "DBConfig(url=%s, run_migrations=%s, alembic_config=%s, metadata_modules=%s)",
        url, run_migrations, alembic_config, modules or "[]",
    )
    return DBConfig(url=url, run_migrations=run_migrations, alembic_config=alembic_config, metadata_modules=modules)


# --- Утилиты ---------------------------------------------------------------------

def _is_sqlite(url: str) -> bool:
    return url.startswith("sqlite+")

def _is_postgres(url: str) -> bool:
    return url.startswith("postgresql+")

def _make_engine(url: str) -> AsyncEngine:
    """
    Создаёт AsyncEngine. Для тестов используем NullPool, чтобы изолировать соединения.
    Для SQLite включаем foreign_keys.
    """
    engine = create_async_engine(
        url,
        echo=False,
        poolclass=NullPool,
        future=True,
    )

    if _is_sqlite(url):
        @event.listens_for(engine.sync_engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA foreign_keys=ON;")
            cursor.close()
    return engine


def _iter_metadata(modules: Iterable[str]):
    """
    Ищет в перечисленных модулях атрибуты: Base.metadata или metadata.
    Возвращает генератор объектов MetaData.
    """
    for mod_name in modules:
        mod = importlib.import_module(mod_name)
        # Попытка 1: SQLAlchemy declarative Base
        for attr in ("Base", "BaseModel", "ModelBase"):
            base = getattr(mod, attr, None)
            if base is not None and hasattr(base, "metadata"):
                yield base.metadata
        # Попытка 2: metadata напрямую
        md = getattr(mod, "metadata", None)
        if md is not None:
            yield md


async def _create_schema_from_metadata(engine: AsyncEngine, modules: Iterable[str]) -> None:
    mds = list(_iter_metadata(modules))
    if not mds:
        logger.warning(
            "METADATA_MODULES указаны, но ни одного metadata не найдено. Схема не будет создана."
        )
        return
    async with engine.begin() as conn:
        for md in mds:
            await conn.run_sync(md.create_all)
    logger.info("Схема создана через metadata: %s", [m.schema for m in mds])


async def _drop_schema_from_metadata(engine: AsyncEngine, modules: Iterable[str]) -> None:
    mds = list(_iter_metadata(modules))
    if not mds:
        return
    async with engine.begin() as conn:
        for md in reversed(mds):
            await conn.run_sync(md.drop_all)
    logger.info("Схема удалена через metadata.")


async def _run_alembic_upgrade_head(alembic_ini_path: str) -> None:
    """
    Прогон Alembic миграций до head в отдельном потоке (alembic — sync).
    Требует: pip install alembic
    """
    from alembic.config import Config
    from alembic import command

    def _upgrade():
        cfg = Config(alembic_ini_path)
        command.upgrade(cfg, "head")

    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _upgrade)
    logger.info("Alembic upgrade head выполнен (%s).", alembic_ini_path)


# --- Фикстуры --------------------------------------------------------------------

@pytest.fixture(scope="session")
def db_config() -> DBConfig:
    return load_db_config()


@pytest_asyncio.fixture(scope="session")
async def engine(db_config: DBConfig) -> AsyncIterator[AsyncEngine]:
    """
    Сессионный AsyncEngine для всех тестов.
    """
    eng = _make_engine(db_config.url)
    try:
        # Прогрев соединения
        async with eng.connect() as conn:
            await conn.execute("SELECT 1")
        logger.info("AsyncEngine готов: %s", db_config.url)
        yield eng
    finally:
        await eng.dispose()
        logger.info("AsyncEngine закрыт.")


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _prepare_database(engine: AsyncEngine, db_config: DBConfig) -> AsyncIterator[None]:
    """
    В начале тестовой сессии: создаём схему либо применяем миграции.
    В конце — чистка (если использовалась metadata и не in-memory SQLite).
    """
    if db_config.run_migrations:
        if not db_config.alembic_config:
            logger.error("RUN_MIGRATIONS=true, но ALEMBIC_CONFIG не указан — миграции пропущены.")
        else:
            await _run_alembic_upgrade_head(db_config.alembic_config)
        # Для миграций не делаем drop здесь — предполагается чистая тестовая БД или детерминированный порядок.
        yield
    else:
        if db_config.metadata_modules:
            await _create_schema_from_metadata(engine, db_config.metadata_modules)
        else:
            logger.warning("METADATA_MODULES не заданы — схема не будет создана автоматически.")
        try:
            yield
        finally:
            # Если это НЕ in-memory sqlite — корректно чистим схему.
            if not (
                _is_sqlite(db_config.url)
                and URL.create(db_config.url).database in (":memory:", None)
            ):
                await _drop_schema_from_metadata(engine, db_config.metadata_modules)


@pytest_asyncio.fixture
async def db_session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """
    Фикстура уровня теста:
    - открывает соединение + верхнеуровневую транзакцию,
    - создаёт AsyncSession, запускает nested transaction (SAVEPOINT),
    - по завершении теста — rollback до чистого состояния.
    """
    async with engine.connect() as conn:
        # Верхняя транзакция на соединении
        trans = await conn.begin()
        try:
            # sessionmaker с привязкой к активному соединению
            maker = async_sessionmaker(bind=conn, class_=AsyncSession, expire_on_commit=False)

            async with maker() as session:
                # Первый сейвпоинт
                nested = await session.begin_nested()

                # Автовосстановление nested транзакции на случай commit внутри тестируемого кода
                @event.listens_for(session.sync_session, "after_transaction_end")
                def _restart_savepoint(sess, transaction):
                    # Восстанавливаем nested, если верхнеуровневая активна и предыдущая была nested
                    if transaction.nested and not sess.in_nested_transaction():
                        try:
                            sess.begin_nested()
                        except Exception as e:
                            logger.exception("Не удалось восстановить nested транзакцию: %s", e)

                yield session

                # Явный rollback nested
                if nested.is_active:
                    await nested.rollback()
        finally:
            # Rollback верхней транзакции
            if trans.is_active:
                await trans.rollback()


# --- Хелперы для интеграционных тестов ------------------------------------------

@asynccontextmanager
async def run_in_transaction(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """
    Контекстный менеджер для ручного использования в интеграционных тестах:
    with await run_in_transaction(engine) as session:
        ... ваши проверки ...
    """
    async with engine.connect() as conn:
        trans = await conn.begin()
        try:
            maker = async_sessionmaker(bind=conn, class_=AsyncSession, expire_on_commit=False)
            async with maker() as session:
                nested = await session.begin_nested()
                yield session
                if nested.is_active:
                    await nested.rollback()
        finally:
            if trans.is_active:
                await trans.rollback()


# --- Опционально: интеграция с FastAPI ------------------------------------------

def override_fastapi_get_session(app, dependency, session: AsyncSession):
    """
    Утилита для переопределения FastAPI-зависимости get_session в тестах:
        from fastapi.testclient import TestClient
        app.dependency_overrides[get_session] = lambda: session
    """
    app.dependency_overrides[dependency] = lambda: session
    return app
