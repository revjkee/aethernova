# backend/src/db.py
from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
from typing import AsyncIterator, Optional, Sequence

from sqlalchemy import event, MetaData
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

# -----------------------------------------------------------------------------
# ЛОГИРОВАНИЕ
# -----------------------------------------------------------------------------
logger = logging.getLogger("db")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# -----------------------------------------------------------------------------
# НАСТРОЙКИ И ОКРУЖЕНИЕ (без сторонних зависимостей)
# -----------------------------------------------------------------------------
def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    val = os.getenv(name, default)
    return val if val is not None and val != "" else default


DB_PRIMARY_URL = _env("DB_PRIMARY_URL")  # например: postgresql+asyncpg://user:pass@host:5432/db
DB_READ_REPLICAS = _env("DB_READ_REPLICAS")  # CSV из URL для чтения (опционально)

# Пул/соединение
DB_POOL_SIZE = int(_env("DB_POOL_SIZE", "10"))
DB_MAX_OVERFLOW = int(_env("DB_MAX_OVERFLOW", "20"))
DB_POOL_TIMEOUT_SEC = int(_env("DB_POOL_TIMEOUT_SEC", "30"))
DB_POOL_RECYCLE_SEC = int(_env("DB_POOL_RECYCLE_SEC", "1800"))  # 30 минут
DB_POOL_PRE_PING = _env("DB_POOL_PRE_PING", "true").lower() == "true"

# Политики сеанса на стороне PostgreSQL
DB_STATEMENT_TIMEOUT_MS = int(_env("DB_STATEMENT_TIMEOUT_MS", "15000"))  # 15 секунд
DB_LOCK_TIMEOUT_MS = int(_env("DB_LOCK_TIMEOUT_MS", "5000"))  # 5 секунд
DB_IDLE_IN_TX_SESSION_TIMEOUT_MS = int(
    _env("DB_IDLE_IN_TX_SESSION_TIMEOUT_MS", "30000")
)

# Таймауты на уровне приложения
DB_CONNECT_TIMEOUT_SEC = int(_env("DB_CONNECT_TIMEOUT_SEC", "10"))
DB_SHUTDOWN_GRACEFUL_SEC = int(_env("DB_SHUTDOWN_GRACEFUL_SEC", "10"))

# Лимит для логирования "медленных" запросов
DB_SLOW_QUERY_MS = int(_env("DB_SLOW_QUERY_MS", "1000"))

# Часовой пояс сеанса
DB_TIMEZONE = _env("DB_TIMEZONE", "UTC")

# -----------------------------------------------------------------------------
# БАЗА ORM И СХЕМА ИМЕНОВАНИЯ (дружелюбно к Alembic автогенерации)
# -----------------------------------------------------------------------------
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


# -----------------------------------------------------------------------------
# СОБЫТИЯ ДВИЖКА/ПОДКЛЮЧЕНИЯ
# -----------------------------------------------------------------------------
def _install_sql_events(engine: AsyncEngine) -> None:
    """
    Устанавливает:
    - on_connect политики (statement_timeout, lock_timeout, idle_in_tx, timezone)
    - измерение "медленных" запросов
    """

    @event.listens_for(engine.sync_engine, "connect")
    def _on_connect(dbapi_conn, conn_record):  # type: ignore[no-redef]
        # Настройки сеанса PostgreSQL — безопасны для pgbouncer в режиме session.
        with dbapi_conn.cursor() as cur:
            # statement_timeout/lock_timeout/idle_in_transaction_session_timeout
            cur.execute(f"SET SESSION statement_timeout = {DB_STATEMENT_TIMEOUT_MS}")
            cur.execute(f"SET SESSION lock_timeout = {DB_LOCK_TIMEOUT_MS}")
            cur.execute(
                f"SET SESSION idle_in_transaction_session_timeout = {DB_IDLE_IN_TX_SESSION_TIMEOUT_MS}"
            )
            # Часовой пояс
            cur.execute(f"SET TIME ZONE '{DB_TIMEZONE}'")

    @event.listens_for(engine.sync_engine, "before_cursor_execute")
    def _before_cursor_execute(conn, cursor, statement, parameters, context, executemany):  # type: ignore[no-redef]
        context._query_start_time = time.perf_counter()

    @event.listens_for(engine.sync_engine, "after_cursor_execute")
    def _after_cursor_execute(conn, cursor, statement, parameters, context, executemany):  # type: ignore[no-redef]
        start = getattr(context, "_query_start_time", None)
        if start is None:
            return
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        if elapsed_ms >= DB_SLOW_QUERY_MS:
            # Логируем медленные запросы без параметров (могут включать секреты)
            logger.warning("Slow query: %.1f ms | %s", elapsed_ms, statement)


# -----------------------------------------------------------------------------
# ФАБРИКА ДВИЖКОВ (PRIMARY + READ REPLICAS)
# -----------------------------------------------------------------------------
class EngineFactory:
    _primary: Optional[AsyncEngine] = None
    _replicas: list[AsyncEngine] = []
    _session_maker_rw: Optional[async_sessionmaker[AsyncSession]] = None
    _session_maker_ro: Optional[async_sessionmaker[AsyncSession]] = None

    @classmethod
    def _create_engine(cls, url: str) -> AsyncEngine:
        if not url or "://" not in url:
            raise ValueError("DB URL is not configured or invalid.")

        logger.info("Creating AsyncEngine for %s", url.split("@")[-1])
        eng = create_async_engine(
            url,
            pool_size=DB_POOL_SIZE,
            max_overflow=DB_MAX_OVERFLOW,
            pool_timeout=DB_POOL_TIMEOUT_SEC,
            pool_recycle=DB_POOL_RECYCLE_SEC,
            pool_pre_ping=DB_POOL_PRE_PING,
            connect_args={"timeout": DB_CONNECT_TIMEOUT_SEC},  # asyncpg
            future=True,
        )
        _install_sql_events(eng)
        return eng

    @classmethod
    def init(cls) -> None:
        """Инициализация фабрики (идемпотентна)."""
        if cls._primary is None:
            if not DB_PRIMARY_URL:
                raise RuntimeError("DB_PRIMARY_URL must be set")
            cls._primary = cls._create_engine(DB_PRIMARY_URL)

        if not cls._replicas and DB_READ_REPLICAS:
            urls = [u.strip() for u in DB_READ_REPLICAS.split(",") if u.strip()]
            for u in urls:
                cls._replicas.append(cls._create_engine(u))

        if cls._session_maker_rw is None:
            cls._session_maker_rw = async_sessionmaker(
                bind=cls._primary,
                expire_on_commit=False,
                autoflush=False,
                class_=AsyncSession,
            )

        if cls._session_maker_ro is None:
            # Если реплик нет, читаем с primary
            bind = cls._replicas[0] if cls._replicas else cls._primary
            cls._session_maker_ro = async_sessionmaker(
                bind=bind,
                expire_on_commit=False,
                autoflush=False,
                class_=AsyncSession,
            )

    @classmethod
    def primary(cls) -> AsyncEngine:
        if cls._primary is None:
            cls.init()
        assert cls._primary is not None
        return cls._primary

    @classmethod
    def replicas(cls) -> Sequence[AsyncEngine]:
        if cls._primary is None and not cls._replicas:
            cls.init()
        return tuple(cls._replicas)

    @classmethod
    def sessionmaker_rw(cls) -> async_sessionmaker[AsyncSession]:
        if cls._session_maker_rw is None:
            cls.init()
        assert cls._session_maker_rw is not None
        return cls._session_maker_rw

    @classmethod
    def sessionmaker_ro(cls) -> async_sessionmaker[AsyncSession]:
        if cls._session_maker_ro is None:
            cls.init()
        assert cls._session_maker_ro is not None
        return cls._session_maker_ro

    @classmethod
    async def dispose(cls) -> None:
        """Грациозное завершение — закрыть пулы."""
        engines = [cls._primary] if cls._primary else []
        engines += list(cls._replicas)
        for eng in engines:
            if eng is None:
                continue
            with contextlib.suppress(Exception):
                await asyncio.wait_for(eng.dispose(), timeout=DB_SHUTDOWN_GRACEFUL_SEC)
        cls._primary = None
        cls._replicas = []
        cls._session_maker_rw = None
        cls._session_maker_ro = None


# -----------------------------------------------------------------------------
# УТИЛИТЫ СЕССИИ/ТРАНЗАКЦИИ
# -----------------------------------------------------------------------------
@contextlib.asynccontextmanager
async def session_rw() -> AsyncIterator[AsyncSession]:
    """
    Сеанс для RW-операций. Транзакцию контролируйте явно через provide_transaction(),
    либо вручную с session.begin().
    """
    sm = EngineFactory.sessionmaker_rw()
    async with sm() as s:
        yield s


@contextlib.asynccontextmanager
async def session_ro() -> AsyncIterator[AsyncSession]:
    """
    Сеанс для RO-операций (реплика при наличии). Не открывает транзакцию по умолчанию.
    """
    sm = EngineFactory.sessionmaker_ro()
    async with sm() as s:
        # На стороне PostgreSQL можно ещё выставить default_transaction_read_only = on
        # через роль/пул, но здесь мы не форсируем.
        yield s


@contextlib.asynccontextmanager
async def provide_transaction(
    read_only: bool = False,
) -> AsyncIterator[AsyncSession]:
    """
    Контекст менеджер транзакции.
    - read_only=True: использовать RO-сеанс (без гарантий snapshot isolation вне БД-настроек).
    - read_only=False: использовать RW-сеанс.
    Автоматически фиксирует/откатывает.
    """
    sm = EngineFactory.sessionmaker_ro() if read_only else EngineFactory.sessionmaker_rw()
    async with sm() as s:
        async with s.begin():
            try:
                yield s
            except Exception:
                with contextlib.suppress(Exception):
                    await s.rollback()
                raise


# -----------------------------------------------------------------------------
# FASTAPI DEPENDENCY
# -----------------------------------------------------------------------------
async def get_session_rw() -> AsyncIterator[AsyncSession]:
    async with session_rw() as s:
        yield s


async def get_session_ro() -> AsyncIterator[AsyncSession]:
    async with session_ro() as s:
        yield s


# -----------------------------------------------------------------------------
# ИНИЦИАЛИЗАЦИЯ/ПРОВЕРКА ПОДКЛЮЧЕНИЯ
# -----------------------------------------------------------------------------
async def init_db() -> None:
    """
    Прогревает движок и проверяет подключение SELECT 1.
    Вызывать на старте приложения.
    """
    EngineFactory.init()
    try:
        async with session_ro() as s:
            await s.execute("SELECT 1")
        logger.info("Database connection verified.")
    except Exception as exc:
        logger.exception("Database connectivity check failed: %s", exc)
        raise


async def check_db(timeout_sec: int = 3) -> bool:
    """
    Health-check для ready/liveness проб.
    Возвращает True/False без исключений; ограничен таймаутом.
    """
    try:
        async with asyncio.timeout(timeout_sec):
            async with session_ro() as s:
                await s.execute("SELECT 1")
            return True
    except Exception as exc:
        logger.warning("DB health check failed: %s", exc)
        return False


# -----------------------------------------------------------------------------
# ЖИЗНЕННЫЙ ЦИКЛ ПРИЛОЖЕНИЯ (например, FastAPI lifespan)
# -----------------------------------------------------------------------------
@contextlib.asynccontextmanager
async def lifespan_context(app=None):
    """
    Пример использования:
        app = FastAPI(lifespan=lifespan_context)
    """
    await init_db()
    try:
        yield
    finally:
        await EngineFactory.dispose()


# -----------------------------------------------------------------------------
# ВСПОМОГАТЕЛЬНОЕ: выполняем корутину внутри транзакции RW
# -----------------------------------------------------------------------------
async def run_in_transaction(coro, *, read_only: bool = False):
    """
    Утилита: выполнить произвольную корутину, которой нужен session,
    внутри транзакции. Корутине будет передан session как единственный аргумент.
    """
    async with provide_transaction(read_only=read_only) as s:
        return await coro(s)


# -----------------------------------------------------------------------------
# ПУБЛИЧНЫЕ ЭКСПОРТЫ
# -----------------------------------------------------------------------------
__all__ = [
    "Base",
    "metadata",
    "EngineFactory",
    "session_rw",
    "session_ro",
    "provide_transaction",
    "get_session_rw",
    "get_session_ro",
    "init_db",
    "check_db",
    "lifespan_context",
    "run_in_transaction",
]
