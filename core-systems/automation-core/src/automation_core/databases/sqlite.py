"""
automation_core.databases.sqlite

Промышленный модуль для работы с SQLite через Async SQLAlchemy 2.x (aiosqlite).

Возможности:
- Безопасная сборка DSN (in-memory и файловый режим).
- Корректный выбор пула: StaticPool для :memory:, NullPool для файловой БД.
- Полный набор PRAGMA: foreign_keys, busy_timeout, journal_mode=WAL, synchronous,
  wal_autocheckpoint, journal_size_limit, cache_size, temp_store, mmap_size.
- Фабрики AsyncEngine / async_sessionmaker.
- Контекстный менеджер сессий и транзакций.
- Инициализация/сброс схемы и встроенный healthcheck.
- Сервисные операции: VACUUM, PRAGMA wal_checkpoint(FULL), резервное копирование в файл.

Зависимости:
  SQLAlchemy >= 2.0
  aiosqlite (драйвер для async SQLite)
"""

from __future__ import annotations

import os
import re
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterator, Iterable, Optional, Sequence, Union

from sqlalchemy import event
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool, StaticPool
from sqlalchemy.sql import text


# -------------------------------- Конфигурация ----------------------------------


@dataclass(frozen=True)
class SQLiteConfig:
    """
    Параметры SQLite.

    path                — путь к файлу БД. Если None и memory=True — :memory:
    memory              — in-memory БД (один процесс/инстанс).
    echo                — вывод SQL.
    wal                 — включать WAL в файловом режиме.
    synchronous         — OFF | NORMAL | FULL | EXTRA (только файлы).
    busy_timeout_ms     — таймаут ожидания блокировок. Рекомендуется >= 5000.
    wal_autocheckpoint  — AUTOCHECKPOINT N страниц (0 — по умолчанию SQLite).
    journal_size_limit  — ограничение WAL журнала в байтах (0 — без лимита).
    cache_size_kb       — отрицательное число = кэш в KiB (семантика SQLite).
    temp_store          — DEFAULT | FILE | MEMORY.
    mmap_size_bytes     — включить mmap (0 — отключено).
    """
    path: Optional[Union[str, Path]] = None
    memory: bool = False
    echo: bool = False

    wal: bool = True
    synchronous: str = "NORMAL"
    busy_timeout_ms: int = 5000
    wal_autocheckpoint: int = 1000
    journal_size_limit: int = 64 * 1024 * 1024  # 64 MiB

    cache_size_kb: int = -64 * 1024            # -65536 => 64 MiB кэша
    temp_store: str = "MEMORY"
    mmap_size_bytes: int = 0


# ------------------------------- Утилиты URL/детект -----------------------------


def build_sqlite_url(cfg: SQLiteConfig) -> str:
    """
    Собирает DSN:
      - memory=True  -> sqlite+aiosqlite:///:memory:
      - file         -> sqlite+aiosqlite:///abs/path/to/file.sqlite
    """
    if cfg.memory:
        return "sqlite+aiosqlite:///:memory:"

    path = cfg.path or "data/automation.sqlite3"
    p = Path(path).expanduser().resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    return URL.create("sqlite+aiosqlite", database=str(p)).render_as_string(hide_password=True)


def _is_memory_url(url: str) -> bool:
    if url.endswith(":memory:"):
        return True
    return bool(re.search(r":memory:(\?|$)", url))


# ---------------------------- Установка PRAGMA на connect ------------------------


def _install_pragmas(engine: AsyncEngine, *, cfg: SQLiteConfig, is_memory: bool) -> None:
    """
    Все PRAGMA применяются на каждом новом соединении.
    """
    @event.listens_for(engine.sync_engine, "connect")
    def _on_connect(dbapi_conn, _):
        cur = dbapi_conn.cursor()

        # Общие
        cur.execute("PRAGMA foreign_keys = ON;")
        if cfg.busy_timeout_ms and cfg.busy_timeout_ms > 0:
            cur.execute(f"PRAGMA busy_timeout = {int(cfg.busy_timeout_ms)};")

        # Файловый режим
        if not is_memory:
            if cfg.wal:
                cur.execute("PRAGMA journal_mode = WAL;")
                if cfg.wal_autocheckpoint >= 0:
                    cur.execute(f"PRAGMA wal_autocheckpoint = {int(cfg.wal_autocheckpoint)};")
                if cfg.journal_size_limit >= 0:
                    cur.execute(f"PRAGMA journal_size_limit = {int(cfg.journal_size_limit)};")
            cur.execute(f"PRAGMA synchronous = {cfg.synchronous};")

        # Производительность/кэш
        if isinstance(cfg.cache_size_kb, int):
            cur.execute(f"PRAGMA cache_size = {cfg.cache_size_kb};")
        cur.execute(f"PRAGMA temp_store = {cfg.temp_store};")

        # mmap
        if cfg.mmap_size_bytes and cfg.mmap_size_bytes > 0 and not is_memory:
            cur.execute(f"PRAGMA mmap_size = {int(cfg.mmap_size_bytes)};")

        cur.close()


# ------------------------------ Фабрики Engine/Session --------------------------


def create_sqlite_engine(cfg: SQLiteConfig) -> AsyncEngine:
    """
    Создаёт AsyncEngine с корректным пулом:
      - :memory: -> StaticPool (одно подключение на процесс)
      - file     -> NullPool   (без переиспользования соединений между задачами)
    """
    url = build_sqlite_url(cfg)
    is_memory = _is_memory_url(url)

    engine = create_async_engine(
        url,
        echo=cfg.echo,
        poolclass=StaticPool if is_memory else NullPool,
        future=True,
    )
    _install_pragmas(engine, cfg=cfg, is_memory=is_memory)
    return engine


def create_sqlite_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """
    Возвращает async_sessionmaker с expire_on_commit=False (рекомендуемый режим для async).
    """
    return async_sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)


@asynccontextmanager
async def get_session_ctx(session_maker: async_sessionmaker[AsyncSession]) -> AsyncIterator[AsyncSession]:
    """
    Контекстный менеджер, выдающий AsyncSession и гарантирующий закрытие.
    """
    async with session_maker() as session:
        try:
            yield session
        finally:
            await session.close()


# ------------------------------- Инициализация схемы ----------------------------


async def init_schema(
    engine: AsyncEngine,
    metadata_or_bases: Iterable[object],
    *,
    drop_existing: bool = False,
) -> None:
    """
    Инициализирует схему БД на основе объектов, содержащих атрибут .metadata
    (Declarative Base или MetaData). Идемпотентно.

    drop_existing=True — предварительный drop_all (обратно-упорядоченно).
    """
    metadatas = []
    for item in metadata_or_bases:
        md = getattr(item, "metadata", None)
        if md is None:
            continue
        metadatas.append(md)

    async with engine.begin() as conn:
        if drop_existing:
            for md in reversed(metadatas):
                await conn.run_sync(md.drop_all)
        for md in metadatas:
            await conn.run_sync(md.create_all)


# --------------------------------- Health/Service -------------------------------


async def healthcheck(engine: AsyncEngine) -> bool:
    """
    Простой healthcheck — SELECT 1.
    """
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


async def vacuum(engine: AsyncEngine) -> None:
    """
    VACUUM — обслуживание и дефрагментация файла БД.
    В WAL-режиме SQLite выполнит auto-checkpoint при необходимости.
    """
    async with engine.begin() as conn:
        await conn.execute(text("VACUUM"))


async def wal_checkpoint_full(engine: AsyncEngine) -> None:
    """
    Полный чекпоинт WAL: PRAGMA wal_checkpoint(FULL).
    Полезно перед бэкапом/релизом.
    """
    async with engine.begin() as conn:
        await conn.execute(text("PRAGMA wal_checkpoint(FULL)"))


async def backup_to_file(engine: AsyncEngine, dest_path: Union[str, Path]) -> None:
    """
    Резервное копирование в файл через внутренний механизм SQLite:
      VACUUM INTO 'path';
    Поддерживается SQLite ≥ 3.27.0. Если не поддерживается, будет исключение.
    """
    p = Path(dest_path).expanduser().resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    async with engine.begin() as conn:
        await conn.execute(text(f"VACUUM INTO '{p.as_posix()}'"))


# ------------------------------- Транзакционный хелпер --------------------------


@asynccontextmanager
async def transactional_session(session_maker: async_sessionmaker[AsyncSession]) -> AsyncIterator[AsyncSession]:
    """
    Контекстный менеджер с транзакцией:
        async with transactional_session(SessionLocal) as s:
            ... # s.add(...); s.execute(...)

    Rollback при исключении, commit — при успехе.
    """
    async with session_maker() as session:
        tx = await session.begin()
        try:
            yield session
        except Exception:
            if tx.is_active:
                await tx.rollback()
            raise
        else:
            if tx.is_active:
                await tx.commit()
        finally:
            await session.close()
