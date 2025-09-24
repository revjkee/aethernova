# automation-core/src/automation_core/databases/orm.py
# -*- coding: utf-8 -*-
"""
Промышленная надстройка над SQLAlchemy 2.x для проекта automation-core.

Возможности:
- Конфигурация БД (асинхронные/синхронные движки, пулы, pre_ping, recycle).
- Базовый класс моделей с UUID-первичным ключом и таймстемпами.
- Фабрики сессий (AsyncSession/Session) и безопасный Unit of Work.
- Обобщённый Repository[T] с CRUD-методами и пагинацией.
- Транзакционный декоратор @transactional.
- Пинг БД (health check).
- Мягкий ретрай для временных ошибок.
- Опциональная интеграция с OpenTelemetry (если установлен наш модуль трассировки).

Зависимости:
- sqlalchemy>=2.0
- sqlalchemy[asyncio] для async-режима
- Опционально: asyncpg/aio-mysql и т.п. в зависимости от драйвера.

Примечания:
- Модуль не навязывает конкретный драйвер/СУБД.
- Для PostgreSQL рекомендуется DSN формата: postgresql+asyncpg://user:pass@host:5432/db
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import logging
import math
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import (
    Any,
    AsyncGenerator,
    Callable,
    Dict,
    Generic,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
)

from sqlalchemy import (
    MetaData,
    String,
    event,
    func,
    select,
    text,
)
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError, DBAPIError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session, sessionmaker
from sqlalchemy.types import DateTime
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy import create_engine as create_sync_engine

log = logging.getLogger(__name__)

# ----------------------------- Трассировка (опционально) ----------------------

def _maybe_trace(name: str):
    """
    Возвращает декоратор трассировки, если установлен наш модуль; иначе no-op.
    """
    try:
        from automation_core.observability.tracing import trace_function  # type: ignore
        return trace_function(name, record_args=False)
    except Exception:
        def _noop(fn):
            return fn
        return _noop


# ----------------------------- Конфигурация БД --------------------------------

@dataclass(frozen=True)
class DatabaseConfig:
    # DSN: sync (например, postgresql://) и/или async (например, postgresql+asyncpg://)
    async_dsn: Optional[str] = None
    sync_dsn: Optional[str] = None

    # Логирование SQL и параметры пула
    echo: bool = False
    pool_size: int = 5
    max_overflow: int = 10
    pool_recycle_sec: int = 1800
    pool_pre_ping: bool = True

    # Доп. параметры для драйвера (например, {"timeout": 30})
    connect_args: Mapping[str, Any] = field(default_factory=dict)


# ----------------------------- Базовая модель ---------------------------------

_naming_convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}
metadata = MetaData(naming_convention=_naming_convention)


class Base(DeclarativeBase):
    metadata = metadata

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        doc="UUIDv4 в текстовом представлении для кросс-СУБД совместимости.",
    )
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    def to_dict(self) -> Dict[str, Any]:
        """
        Простая сериализация модели в словарь по именам колонок.
        """
        out: Dict[str, Any] = {}
        for k in self.__mapper__.columns.keys():  # type: ignore[attr-defined]
            out[k] = getattr(self, k)
        return out


# ----------------------------- Движки и фабрики -------------------------------

def create_engine_sync(cfg: DatabaseConfig) -> Engine:
    if not cfg.sync_dsn:
        raise ValueError("sync_dsn не задан")
    eng = create_sync_engine(
        cfg.sync_dsn,
        echo=cfg.echo,
        pool_pre_ping=cfg.pool_pre_ping,
        pool_size=cfg.pool_size,
        max_overflow=cfg.max_overflow,
        pool_recycle=cfg.pool_recycle_sec,
        connect_args=dict(cfg.connect_args),
    )
    return eng


def create_engine_async(cfg: DatabaseConfig) -> AsyncEngine:
    if not cfg.async_dsn:
        raise ValueError("async_dsn не задан")
    aeng = create_async_engine(
        cfg.async_dsn,
        echo=cfg.echo,
        pool_pre_ping=cfg.pool_pre_ping,
        pool_size=cfg.pool_size,
        max_overflow=cfg.max_overflow,
        pool_recycle=cfg.pool_recycle_sec,
        connect_args=dict(cfg.connect_args),
    )
    return aeng


def create_session_factory_sync(eng: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=eng, expire_on_commit=False, autoflush=False, autocommit=False)


def create_session_factory_async(aeng: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(bind=aeng, expire_on_commit=False, autoflush=False)


# ----------------------------- Health Check -----------------------------------

@_maybe_trace("db.ping")
async def db_ping(aeng: AsyncEngine, timeout_sec: float = 5.0) -> bool:
    """
    Простая проверка связи: SELECT 1.
    """
    try:
        async with asyncio.timeout(timeout_sec):
            async with aeng.connect() as conn:
                await conn.execute(text("SELECT 1"))
        return True
    except Exception as e:
        log.warning("DB ping failed: %s", e)
        return False


# ----------------------------- Мягкий ретрай ----------------------------------

def _is_transient_db_error(ex: BaseException) -> bool:
    """
    Простая эвристика: транзиентные ошибки пулов/коннекта/блокировок.
    """
    if isinstance(ex, OperationalError):
        return True
    if isinstance(ex, DBAPIError) and getattr(ex, "connection_invalidated", False):
        return True
    return False


def retry_async(
    *,
    attempts: int = 3,
    base_delay: float = 0.2,
    max_delay: float = 2.0,
    predicate: Callable[[BaseException], bool] = _is_transient_db_error,
):
    """
    Декоратор для корутин: экспоненциальный backoff по транзиентным ошибкам.
    """
    def deco(fn: Callable[..., Any]):
        async def wrapper(*args, **kwargs):
            last_exc: Optional[BaseException] = None
            for i in range(1, attempts + 1):
                try:
                    return await fn(*args, **kwargs)
                except BaseException as e:
                    if not predicate(e) or i == attempts:
                        last_exc = e
                        break
                    delay = min(max_delay, base_delay * (2 ** (i - 1)))
                    await asyncio.sleep(delay)
            assert last_exc is not None
            raise last_exc
        return wrapper
    return deco


# ----------------------------- Unit of Work -----------------------------------

class UnitOfWork:
    """
    Безопасная транзакция для AsyncSession.
    Пример:
        async with UnitOfWork(async_session_factory) as uow:
            repo = Repository(uow.session, MyModel)
            await repo.add(MyModel(...))
            await uow.commit()
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory
        self.session: Optional[AsyncSession] = None
        self._active: bool = False

    async def __aenter__(self) -> "UnitOfWork":
        self.session = self._session_factory()
        self._active = True
        await self.session.__aenter__()  # type: ignore[attr-defined]
        return self

    async def __aexit__(self, exc_type, exc, tb):
        try:
            if exc:
                await self.rollback()
            else:
                # Автокоммит — только если пользователь явно не вызывал rollback
                if self.session is not None and self.session.in_transaction():
                    await self.session.commit()
        finally:
            self._active = False
            if self.session is not None:
                await self.session.__aexit__(exc_type, exc, tb)  # type: ignore[attr-defined]
                self.session = None

    @_maybe_trace("db.uow.commit")
    @retry_async()
    async def commit(self) -> None:
        if not self._active or self.session is None:
            raise RuntimeError("UnitOfWork не активен")
        await self.session.commit()

    @_maybe_trace("db.uow.rollback")
    async def rollback(self) -> None:
        if self.session is not None:
            await self.session.rollback()


# ----------------------------- Репозиторий ------------------------------------

TModel = TypeVar("TModel", bound=Base)


@dataclass(frozen=True)
class Page(Generic[TModel]):
    items: List[TModel]
    total: int
    page: int
    size: int

    @property
    def pages(self) -> int:
        return max(1, math.ceil(self.total / max(1, self.size)))


class Repository(Generic[TModel]):
    """
    Обобщённый репозиторий для SQLAlchemy 2.x (async).
    """

    def __init__(self, session: AsyncSession, model: Type[TModel]) -> None:
        self.session = session
        self.model = model

    @_maybe_trace("db.repo.get")
    async def get(self, id_: str) -> Optional[TModel]:
        return await self.session.get(self.model, id_)

    @_maybe_trace("db.repo.add")
    async def add(self, instance: TModel) -> TModel:
        self.session.add(instance)
        return instance

    @_maybe_trace("db.repo.delete")
    async def delete(self, instance: TModel, *, hard: bool = True) -> None:
        if hard:
            await self.session.delete(instance)  # type: ignore[arg-type]
        else:
            # Реализуйте soft delete у своей модели (например, флаг deleted_at)
            if hasattr(instance, "deleted_at"):
                setattr(instance, "deleted_at", func.now())

    @_maybe_trace("db.repo.list")
    async def list(
        self,
        *,
        where: Optional[Sequence[Any]] = None,
        order_by: Optional[Sequence[Any]] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> List[TModel]:
        stmt = select(self.model)
        if where:
            for cond in where:
                stmt = stmt.where(cond)
        if order_by:
            stmt = stmt.order_by(*order_by)
        if limit is not None:
            stmt = stmt.limit(limit)
        if offset is not None:
            stmt = stmt.offset(offset)
        res = await self.session.execute(stmt)
        return list(res.scalars().all())

    @_maybe_trace("db.repo.paginate")
    async def paginate(
        self,
        *,
        page: int = 1,
        size: int = 50,
        where: Optional[Sequence[Any]] = None,
        order_by: Optional[Sequence[Any]] = None,
    ) -> Page[TModel]:
        page = max(1, int(page))
        size = max(1, int(size))

        # Основной запрос
        stmt = select(self.model)
        if where:
            for cond in where:
                stmt = stmt.where(cond)
        if order_by:
            stmt = stmt.order_by(*order_by)

        # Подсчёт total (обнуляем order_by во избежание ошибок в COUNT)
        count_stmt = select(func.count()).select_from(stmt.order_by(None).subquery())

        total_res = await self.session.execute(count_stmt)
        total = int(total_res.scalar_one())

        data_stmt = stmt.limit(size).offset((page - 1) * size)
        rows = await self.session.execute(data_stmt)
        items = list(rows.scalars().all())
        return Page(items=items, total=total, page=page, size=size)


# ----------------------------- Транзакционный декоратор -----------------------

def transactional(uow_factory: async_sessionmaker[AsyncSession]):
    """
    Декоратор для сервисных методов. Оборачивает в UnitOfWork.
    Пример:
        @transactional(async_session_factory)
        async def create_user(uow: UnitOfWork, dto: UserDTO): ...
    """
    def deco(fn: Callable[..., Any]):
        async def wrapper(*args, **kwargs):
            async with UnitOfWork(uow_factory) as uow:
                kwargs["uow"] = uow
                return await fn(*args, **kwargs)
        return wrapper
    return deco


# ----------------------------- Утилиты интеграции -----------------------------

async def get_async_session(session_factory: async_sessionmaker[AsyncSession]) -> AsyncGenerator[AsyncSession, None]:
    """
    Генератор для DI (например, в FastAPI Depends).
    """
    async with session_factory() as session:
        yield session


# ----------------------------- Вспомогательные хукы ---------------------------

@event.listens_for(Base, "before_update", propagate=True)
def _update_timestamp(mapper, connection, target):  # pragma: no cover (тонкая интеграция SQLA)
    """
    Перестраховка: если СУБД не поддерживает onupdate=func.now() — обновим здесь.
    """
    if hasattr(target, "updated_at"):
        setattr(target, "updated_at", func.now())


# ----------------------------- Пример инициализации ---------------------------

class Database:
    """
    Высокоуровневая обёртка для удобного управления движками/сессиями.
    """

    def __init__(self, cfg: DatabaseConfig) -> None:
        self.cfg = cfg
        self.engine: Optional[Engine] = None
        self.async_engine: Optional[AsyncEngine] = None
        self.Session: Optional[sessionmaker[Session]] = None
        self.AsyncSession: Optional[async_sessionmaker[AsyncSession]] = None

    def init_sync(self) -> None:
        self.engine = create_engine_sync(self.cfg)
        self.Session = create_session_factory_sync(self.engine)

    def init_async(self) -> None:
        self.async_engine = create_engine_async(self.cfg)
        self.AsyncSession = create_session_factory_async(self.async_engine)

    async def dispose(self) -> None:
        if self.async_engine is not None:
            await self.async_engine.dispose()
        if self.engine is not None:
            self.engine.dispose()


# ----------------------------- Быстрый старт ----------------------------------

def quick_start_from_env(prefix: str = "DB_") -> Database:
    """
    Быстрая инициализация из переменных окружения:
      DB_ASYNC_DSN, DB_SYNC_DSN, DB_ECHO, DB_POOL_SIZE, DB_MAX_OVERFLOW, DB_POOL_RECYCLE_SEC, DB_PRE_PING
    """
    cfg = DatabaseConfig(
        async_dsn=os.getenv(f"{prefix}ASYNC_DSN"),
        sync_dsn=os.getenv(f"{prefix}SYNC_DSN"),
        echo=os.getenv(f"{prefix}ECHO", "0") in ("1", "true", "True"),
        pool_size=int(os.getenv(f"{prefix}POOL_SIZE", "5")),
        max_overflow=int(os.getenv(f"{prefix}MAX_OVERFLOW", "10")),
        pool_recycle_sec=int(os.getenv(f"{prefix}POOL_RECYCLE_SEC", "1800")),
        pool_pre_ping=os.getenv(f"{prefix}PRE_PING", "1") in ("1", "true", "True"),
        connect_args={},
    )
    db = Database(cfg)
    if cfg.async_dsn:
        db.init_async()
    if cfg.sync_dsn:
        db.init_sync()
    return db
