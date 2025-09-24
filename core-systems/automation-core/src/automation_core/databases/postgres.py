# automation-core/src/automation_core/databases/postgres.py
# -*- coding: utf-8 -*-
"""
Промышленный клиент PostgreSQL (psycopg 3) с синхронным и асинхронным пулами.

Ключевые свойства:
- psycopg 3/psycopg_pool: пулы ConnectionPool / AsyncConnectionPool, колбэк configure,
  проверка соединений (check_connection). Безопасная работа в многопоточной/async-среде.
- Транзакции: настройки isolation_level/read_only/deferrable до начала транзакции, локальные
  таймауты через `SET LOCAL statement_timeout`, опционально `lock_timeout`.
- Фабрики строк: tuple_row / dict_row / namedtuple_row / scalar_row.
- Безопасная сборка SQL через psycopg.sql (SQL/Identifier/Literal).
- Утилиты: healthcheck, fetch_one/fetch_all/fetch_val, execute/execute_many, экспоненциальный retry
  для временных ошибок (например, SerializationFailure/DeadlockDetected).

Зависимости: psycopg>=3, psycopg_pool.
"""

from __future__ import annotations

import contextlib
import dataclasses
import logging
import os
import time
from dataclasses import dataclass
from typing import (
    Any,
    AsyncIterator,
    Callable,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
)

import psycopg
from psycopg import sql
from psycopg.rows import tuple_row, dict_row, namedtuple_row, scalar_row
from psycopg.errors import (
    SerializationFailure,
    DeadlockDetected,
    CannotConnectNow,
    OperationalError,
)
from psycopg_pool import ConnectionPool, AsyncConnectionPool

LOG = logging.getLogger(__name__)

# Псевдонимы для безопасной композиции SQL
SQL = sql.SQL
Identifier = sql.Identifier
Literal = sql.Literal

T = TypeVar("T")

# Изоляция транзакций (enum psycopg)
Isolation = psycopg.IsolationLevel


@dataclass(frozen=True)
class PostgresConfig:
    """
    Конфигурация подключения/пула. Может собираться из переменных окружения.
    """
    dsn: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    dbname: Optional[str] = None
    user: Optional[str] = None
    password: Optional[str] = None
    sslmode: Optional[str] = None
    application_name: str = "automation-core"

    min_size: int = 1
    max_size: Optional[int] = 10
    pool_timeout_s: float = 30.0

    # Сессионные таймауты по умолчанию (мс)
    default_statement_timeout_ms: Optional[int] = None
    default_lock_timeout_ms: Optional[int] = None

    # Настройки транзакций по умолчанию
    isolation_level: Optional[Isolation] = None
    read_only: Optional[bool] = None
    deferrable: Optional[bool] = None

    # Фабрика строк по умолчанию
    row_factory: str = "tuple"  # tuple|dict|namedtuple|scalar

    # Немедленно открывать пул (sync); для async — open() вручную
    open_immediately: bool = True

    @staticmethod
    def from_env(prefix: str = "PG_") -> "PostgresConfig":
        def _b(s: Optional[str]) -> bool:
            return str(s).lower() in {"1", "true", "yes", "y", "on"}
        def _b_or_none(s: Optional[str]) -> Optional[bool]:
            return None if s is None else _b(s)

        url = os.getenv("DATABASE_URL")
        return PostgresConfig(
            dsn=url,
            host=os.getenv(f"{prefix}HOST"),
            port=int(os.getenv(f"{prefix}PORT", "0") or 0) or None,
            dbname=os.getenv(f"{prefix}DBNAME") or os.getenv("PGDATABASE"),
            user=os.getenv(f"{prefix}USER") or os.getenv("PGUSER"),
            password=os.getenv(f"{prefix}PASSWORD") or os.getenv("PGPASSWORD"),
            sslmode=os.getenv(f"{prefix}SSLMODE") or os.getenv("PGSSLMODE"),
            application_name=os.getenv(f"{prefix}APPNAME", "automation-core"),
            min_size=int(os.getenv(f"{prefix}POOL_MIN", "1")),
            max_size=int(os.getenv(f"{prefix}POOL_MAX", "10")),
            pool_timeout_s=float(os.getenv(f"{prefix}POOL_TIMEOUT_S", "30")),
            default_statement_timeout_ms=int(os.getenv(f"{prefix}STATEMENT_TIMEOUT_MS", "0") or 0) or None,
            default_lock_timeout_ms=int(os.getenv(f"{prefix}LOCK_TIMEOUT_MS", "0") or 0) or None,
            isolation_level=_isolation_from_str(os.getenv(f"{prefix}ISOLATION")),
            read_only=_b_or_none(os.getenv(f"{prefix}READ_ONLY")),
            deferrable=_b_or_none(os.getenv(f"{prefix}DEFERRABLE")),
            row_factory=os.getenv(f"{prefix}ROW_FACTORY", "tuple"),
            open_immediately=_b(os.getenv(f"{prefix}OPEN_POOL", "true")),
        )

    def _conninfo(self) -> str:
        if self.dsn:
            return self.dsn
        parts: List[str] = []
        if self.host:
            parts.append(f"host={self.host}")
        if self.port:
            parts.append(f"port={self.port}")
        if self.dbname:
            parts.append(f"dbname={self.dbname}")
        if self.user:
            parts.append(f"user={self.user}")
        if self.password:
            parts.append(f"password={self.password}")
        if self.sslmode:
            parts.append(f"sslmode={self.sslmode}")
        parts.append(f"application_name={self.application_name}")
        return " ".join(parts)

    def _row_factory(self):
        return {
            "tuple": tuple_row,
            "dict": dict_row,
            "namedtuple": namedtuple_row,
            "scalar": scalar_row,
        }.get(self.row_factory, tuple_row)


def _isolation_from_str(val: Optional[str]) -> Optional[Isolation]:
    if not val:
        return None
    key = val.strip().upper().replace(" ", "_")
    return getattr(psycopg.IsolationLevel, key, None)


# --------------------------- СИНХРОННЫЙ ПУЛ -----------------------------------

class PostgresPool:
    """
    Обёртка над psycopg_pool.ConnectionPool с удобными методами.
    """

    def __init__(self, cfg: PostgresConfig):
        self._cfg = dataclasses.replace(cfg)
        self._pool = ConnectionPool(
            conninfo=self._cfg._conninfo(),
            min_size=self._cfg.min_size,
            max_size=self._cfg.max_size,
            timeout=self._cfg.pool_timeout_s,
            open=self._cfg.open_immediately,
            configure=self._configure_connection,  # вызывается при создании соединения
            check=ConnectionPool.check_connection,  # базовая проверка соединения
            name=f"pg-sync-{self._cfg.application_name}",
        )

    def _configure_connection(self, conn: psycopg.Connection) -> None:
        # Уровень соединения: фабрика строк и транзакционные свойства
        conn.row_factory = self._cfg._row_factory()
        if self._cfg.isolation_level is not None:
            conn.isolation_level = self._cfg.isolation_level
        if self._cfg.read_only is not None:
            conn.read_only = self._cfg.read_only
        if self._cfg.deferrable is not None:
            conn.deferrable = self._cfg.deferrable
        # Сессионные таймауты
        with conn:
            if self._cfg.default_statement_timeout_ms is not None:
                conn.execute(SQL("SET statement_timeout = %s"), (self._cfg.default_statement_timeout_ms,))
            if self._cfg.default_lock_timeout_ms is not None:
                conn.execute(SQL("SET lock_timeout = %s"), (self._cfg.default_lock_timeout_ms,))

    # Контекст-менеджер пула
    def __enter__(self) -> "PostgresPool":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # Соединение из пула
    @contextlib.contextmanager
    def connection(self) -> Iterator[psycopg.Connection]:
        with self._pool.connection(timeout=self._cfg.pool_timeout_s) as conn:
            yield conn  # commit/rollback при выходе

    # Явная транзакция с опциями
    @contextlib.contextmanager
    def transaction(
        self,
        *,
        isolation: Optional[Isolation] = None,
        read_only: Optional[bool] = None,
        deferrable: Optional[bool] = None,
        statement_timeout_ms: Optional[int] = None,
        lock_timeout_ms: Optional[int] = None,
    ) -> Iterator[psycopg.Connection]:
        with self.connection() as conn:
            if isolation is not None:
                conn.isolation_level = isolation
            if read_only is not None:
                conn.read_only = read_only
            if deferrable is not None:
                conn.deferrable = deferrable
            with conn:
                if statement_timeout_ms is not None:
                    conn.execute(SQL("SET LOCAL statement_timeout = %s"), (statement_timeout_ms,))
                if lock_timeout_ms is not None:
                    conn.execute(SQL("SET LOCAL lock_timeout = %s"), (lock_timeout_ms,))
                yield conn

    # CRUD-хелперы
    def execute(
        self,
        query: Union[str, SQL],
        params: Optional[Union[Sequence[Any], Mapping[str, Any]]] = None,
    ) -> int:
        with self.connection() as conn:
            cur = conn.execute(query, params)
            return cur.rowcount

    def execute_many(
        self,
        query: Union[str, SQL],
        seq_of_params: Iterable[Union[Sequence[Any], Mapping[str, Any]]],
    ) -> int:
        affected = 0
        with self.connection() as conn:
            for params in seq_of_params:
                cur = conn.execute(query, params)
                affected += cur.rowcount
        return affected

    def fetch_all(
        self,
        query: Union[str, SQL],
        params: Optional[Union[Sequence[Any], Mapping[str, Any]]] = None,
        *,
        row_factory=None,
    ) -> List[Any]:
        with self.connection() as conn:
            if row_factory:
                cur = conn.cursor(row_factory=row_factory)
                cur.execute(query, params)
            else:
                cur = conn.execute(query, params)
            return list(cur.fetchall())

    def fetch_one(
        self,
        query: Union[str, SQL],
        params: Optional[Union[Sequence[Any], Mapping[str, Any]]] = None,
        *,
        row_factory=None,
    ) -> Optional[Any]:
        with self.connection() as conn:
            if row_factory:
                cur = conn.cursor(row_factory=row_factory)
                cur.execute(query, params)
            else:
                cur = conn.execute(query, params)
            return cur.fetchone()

    def fetch_val(
        self,
        query: Union[str, SQL],
        params: Optional[Union[Sequence[Any], Mapping[str, Any]]] = None,
    ) -> Any:
        with self.connection() as conn:
            cur = conn.cursor(row_factory=scalar_row)
            cur.execute(query, params)
            return cur.fetchone()

    def healthcheck(self) -> bool:
        try:
            return self.fetch_val("SELECT 1") == 1
        except Exception as e:  # pragma: no cover
            LOG.warning("postgres_healthcheck_failed", extra={"error": repr(e)})
            return False

    def close(self) -> None:
        self._pool.close()


# --------------------------- АСИНХРОННЫЙ ПУЛ ----------------------------------

class AsyncPostgresPool:
    """
    Асинхронная обёртка над psycopg_pool.AsyncConnectionPool.
    """

    def __init__(self, cfg: PostgresConfig):
        self._cfg = dataclasses.replace(cfg)
        self._pool = AsyncConnectionPool(
            conninfo=self._cfg._conninfo(),
            min_size=self._cfg.min_size,
            max_size=self._cfg.max_size,
            timeout=self._cfg.pool_timeout_s,
            open=False,  # для async открываем явно через open()
            configure=self._configure_connection,
            check=AsyncConnectionPool.check_connection,
            name=f"pg-async-{self._cfg.application_name}",
        )

    async def open(self) -> None:
        await self._pool.open(wait=True)

    async def close(self) -> None:
        await self._pool.close()

    async def __aenter__(self) -> "AsyncPostgresPool":
        await self.open()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def _configure_connection(self, conn: psycopg.AsyncConnection) -> None:
        conn.row_factory = self._cfg._row_factory()
        # Для async-соединений используются set_* методы
        if self._cfg.isolation_level is not None:
            await conn.set_isolation_level(self._cfg.isolation_level)
        if self._cfg.read_only is not None:
            await conn.set_read_only(self._cfg.read_only)
        if self._cfg.deferrable is not None:
            await conn.set_deferrable(self._cfg.deferrable)
        async with conn:
            if self._cfg.default_statement_timeout_ms is not None:
                await conn.execute(SQL("SET statement_timeout = %s"), (self._cfg.default_statement_timeout_ms,))
            if self._cfg.default_lock_timeout_ms is not None:
                await conn.execute(SQL("SET lock_timeout = %s"), (self._cfg.default_lock_timeout_ms,))

    @contextlib.asynccontextmanager
    async def connection(self) -> AsyncIterator[psycopg.AsyncConnection]:
        async with self._pool.connection(timeout=self._cfg.pool_timeout_s) as conn:
            yield conn

    @contextlib.asynccontextmanager
    async def transaction(
        self,
        *,
        isolation: Optional[Isolation] = None,
        read_only: Optional[bool] = None,
        deferrable: Optional[bool] = None,
        statement_timeout_ms: Optional[int] = None,
        lock_timeout_ms: Optional[int] = None,
    ) -> AsyncIterator[psycopg.AsyncConnection]:
        async with self.connection() as conn:
            if isolation is not None:
                await conn.set_isolation_level(isolation)
            if read_only is not None:
                await conn.set_read_only(read_only)
            if deferrable is not None:
                await conn.set_deferrable(deferrable)
            async with conn:
                if statement_timeout_ms is not None:
                    await conn.execute(SQL("SET LOCAL statement_timeout = %s"), (statement_timeout_ms,))
                if lock_timeout_ms is not None:
                    await conn.execute(SQL("SET LOCAL lock_timeout = %s"), (lock_timeout_ms,))
                yield conn

    # CRUD-хелперы (async)
    async def execute(
        self,
        query: Union[str, SQL],
        params: Optional[Union[Sequence[Any], Mapping[str, Any]]] = None,
    ) -> int:
        async with self.connection() as conn:
            cur = await conn.execute(query, params)
            return cur.rowcount

    async def execute_many(
        self,
        query: Union[str, SQL],
        seq_of_params: Iterable[Union[Sequence[Any], Mapping[str, Any]]],
    ) -> int:
        affected = 0
        async with self.connection() as conn:
            for params in seq_of_params:
                cur = await conn.execute(query, params)
                affected += cur.rowcount
        return affected

    async def fetch_all(
        self,
        query: Union[str, SQL],
        params: Optional[Union[Sequence[Any], Mapping[str, Any]]] = None,
        *,
        row_factory=None,
    ) -> List[Any]:
        async with self.connection() as conn:
            if row_factory:
                cur = await conn.cursor(row_factory=row_factory)
                await cur.execute(query, params)
            else:
                cur = await conn.execute(query, params)
            return await cur.fetchall()

    async def fetch_one(
        self,
        query: Union[str, SQL],
        params: Optional[Union[Sequence[Any], Mapping[str, Any]]] = None,
        *,
        row_factory=None,
    ) -> Optional[Any]:
        async with self.connection() as conn:
            if row_factory:
                cur = await conn.cursor(row_factory=row_factory)
                await cur.execute(query, params)
            else:
                cur = await conn.execute(query, params)
            return await cur.fetchone()

    async def fetch_val(
        self,
        query: Union[str, SQL],
        params: Optional[Union[Sequence[Any], Mapping[str, Any]]] = None,
    ) -> Any:
        async with self.connection() as conn:
            cur = await conn.cursor(row_factory=scalar_row)
            await cur.execute(query, params)
            return await cur.fetchone()

    async def healthcheck(self) -> bool:
        try:
            return await self.fetch_val("SELECT 1") == 1
        except Exception as e:  # pragma: no cover
            LOG.warning("postgres_healthcheck_failed_async", extra={"error": repr(e)})
            return False


# --------------------------- Утилиты ------------------------------------------

def safe_ident(name: str) -> Identifier:
    """Безопасная идентификация (имя схемы/таблицы/колонки) для форматирования SQL."""
    return Identifier(name)

def compose_select_all(schema: Optional[str], table: str) -> SQL:
    """Пример безопасной сборки SELECT * FROM <schema>.<table>."""
    if schema:
        return SQL("SELECT * FROM {}.{}").format(Identifier(schema), Identifier(table))
    return SQL("SELECT * FROM {}").format(Identifier(table))

def is_transient_error(exc: BaseException) -> bool:
    """Эвристика для временных ошибок, стоящих повтора."""
    return isinstance(exc, (SerializationFailure, DeadlockDetected, CannotConnectNow, OperationalError))

def retry(
    fn: Callable[[], T],
    *,
    attempts: int = 3,
    base_delay_s: float = 0.1,
    factor: float = 2.0,
    max_delay_s: float = 2.0,
) -> T:
    """
    Простой экспоненциальный retry с ограничением максимальной задержки.
    """
    last: Optional[Exception] = None
    delay = base_delay_s
    for i in range(1, max(1, attempts) + 1):
        try:
            return fn()
        except Exception as e:  # pragma: no cover
            last = e
            if not is_transient_error(e) or i >= attempts:
                raise
            time.sleep(min(max_delay_s, delay))
            delay *= factor
    assert last is not None
    raise last
