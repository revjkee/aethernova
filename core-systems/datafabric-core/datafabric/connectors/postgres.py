# datafabric-core/datafabric/connectors/postgres.py
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import logging
import os
import random
import re
import time
from typing import Any, AsyncIterator, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from sqlalchemy import text
from sqlalchemy.engine import URL
from sqlalchemy.exc import DBAPIError, OperationalError, InterfaceError, SQLAlchemyError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

logger = logging.getLogger("datafabric.postgres")

# ======================================================================================
# Метрики (минимальный интерфейс, совместим с другими модулями)
# ======================================================================================

class MetricsSink:
    async def incr(self, name: str, value: int = 1, tags: Optional[Dict[str, str]] = None) -> None: ...
    async def observe(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None: ...

class NullMetrics(MetricsSink):
    async def incr(self, name: str, value: int = 1, tags: Optional[Dict[str, str]] = None) -> None:
        return
    async def observe(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        return

# ======================================================================================
# Конфигурация
# ======================================================================================

@dataclasses.dataclass(frozen=True)
class PostgresConfig:
    dsn: str                                # postgresql+asyncpg://user:pass@host:5432/db?sslmode=prefer
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout_s: int = 30
    pool_recycle_s: int = 1800
    echo: bool = False

    # Таймауты на стороне сервера для запроса (через SET LOCAL)
    statement_timeout_ms: int = 30_000      # 30s
    lock_timeout_ms: int = 5_000            # 5s
    idle_in_transaction_session_timeout_ms: int = 60_000

    # Параметры retry уровня приложения
    retry_max_attempts: int = 5
    retry_base_delay_ms: int = 100
    retry_max_delay_ms: int = 3000

    # Режимы безопасности
    read_only: bool = False
    app_name: str = "datafabric-core"

# ======================================================================================
# Фабрика движка и sessionmaker
# ======================================================================================

@dataclasses.dataclass
class PostgresConnector:
    engine: AsyncEngine
    session_maker: async_sessionmaker[AsyncSession]
    cfg: PostgresConfig
    metrics: MetricsSink

    @classmethod
    def create(cls, cfg: PostgresConfig, metrics: Optional[MetricsSink] = None) -> "PostgresConnector":
        """
        Создает AsyncEngine с пулом и sessionmaker. Не открывает соединение немедленно (lazy).
        """
        # Безопасно прокидываем application_name
        url = URL.create(cfg.dsn) if isinstance(cfg.dsn, str) else cfg.dsn  # type: ignore
        # SQLAlchemy URL.create не парсит query для строки — оставляем как есть
        connect_args: Dict[str, Any] = {
            "server_settings": {
                "application_name": cfg.app_name,
            }
        }

        engine = create_async_engine(
            str(url),
            echo=cfg.echo,
            pool_size=cfg.pool_size,
            max_overflow=cfg.max_overflow,
            pool_timeout=cfg.pool_timeout_s,
            pool_recycle=cfg.pool_recycle_s,
            connect_args=connect_args,
        )

        session_maker = async_sessionmaker(
            bind=engine,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )

        return cls(engine=engine, session_maker=session_maker, cfg=cfg, metrics=metrics or NullMetrics())

    async def close(self) -> None:
        """
        Graceful shutdown: закрывает пул и ожидает завершение фоновых задач драйвера.
        """
        await self.engine.dispose()
        await self.metrics.incr("pg.closed")

# ======================================================================================
# Вспомогательные утилиты
# ======================================================================================

_RE_SAFE_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_.$]*$")

def _jit_backoff(attempt: int, base_ms: int, max_ms: int) -> float:
    exp = min(max_ms, base_ms * (2 ** attempt))
    return random.uniform(base_ms, exp) / 1000.0

def _is_retryable(exc: BaseException) -> bool:
    # asyncpg/psycopg2 коды ошибок, временные сетевые сбои и конфликты блокировок
    if isinstance(exc, (OperationalError, InterfaceError)):
        return True
    if isinstance(exc, DBAPIError) and getattr(exc, "orig", None) is not None:
        # SQLSTATE проверки
        sqlstate = getattr(getattr(exc, "orig", None), "sqlstate", None)
        if sqlstate in {"40001", "40P01"}:  # serialization_failure, deadlock_detected
            return True
    return False

@contextlib.asynccontextmanager
async def session_scope(
    connector: PostgresConnector,
    *,
    read_only: Optional[bool] = None,
) -> AsyncIterator[AsyncSession]:
    """
    Асинхронный контекстный менеджер с установкой безопасных локальных параметров:
    - statement_timeout, lock_timeout, idle_in_transaction_session_timeout
    - read only (при необходимости)
    Гарантирует commit/rollback.
    """
    ro = connector.cfg.read_only if read_only is None else read_only
    async with connector.session_maker() as session:
        # Устанавливаем SET LOCAL – действует в рамках транзакции
        await session.execute(
            text(
                "SET LOCAL statement_timeout = :st; "
                "SET LOCAL lock_timeout = :lt; "
                "SET LOCAL idle_in_transaction_session_timeout = :it; "
                + ("SET LOCAL default_transaction_read_only = on; " if ro else "RESET default_transaction_read_only; ")
            ),
            {
                "st": connector.cfg.statement_timeout_ms,
                "lt": connector.cfg.lock_timeout_ms,
                "it": connector.cfg.idle_in_transaction_session_timeout_ms,
            },
        )
        try:
            yield session
            await session.commit()
        except Exception:
            with contextlib.suppress(Exception):
                await session.rollback()
            raise

# ======================================================================================
# Базовые операции с retry
# ======================================================================================

async def _with_retry(
    connector: PostgresConnector,
    coro_factory: Callable[[], Any],
    *,
    op_name: str,
) -> Any:
    attempt = 0
    while True:
        t0 = time.monotonic()
        try:
            res = await coro_factory()
            await connector.metrics.observe(f"pg.{op_name}.latency_ms", (time.monotonic() - t0) * 1000.0)
            return res
        except Exception as e:
            if not _is_retryable(e) or attempt >= connector.cfg.retry_max_attempts:
                await connector.metrics.incr(f"pg.{op_name}.error")
                raise
            await connector.metrics.incr(f"pg.{op_name}.retry")
            await asyncio.sleep(_jit_backoff(attempt, connector.cfg.retry_base_delay_ms, connector.cfg.retry_max_delay_ms))
            attempt += 1

# --------------------------------------------------------------------------------------

async def execute(
    connector: PostgresConnector,
    sql: str,
    params: Optional[Mapping[str, Any]] = None,
) -> int:
    """
    Выполняет DML/DDL. Возвращает rowcount.
    """
    async def _op():
        async with session_scope(connector) as s:
            r = await s.execute(text(sql), params or {})
            return r.rowcount or 0

    return await _with_retry(connector, _op, op_name="execute")

async def fetch_all(
    connector: PostgresConnector,
    sql: str,
    params: Optional[Mapping[str, Any]] = None,
) -> List[Mapping[str, Any]]:
    """
    Возвращает список словарей.
    """
    async def _op():
        async with session_scope(connector) as s:
            res = await s.execute(text(sql), params or {})
            rows = res.mappings().all()
            return [dict(r) for r in rows]

    return await _with_retry(connector, _op, op_name="fetch_all")

async def fetch_one(
    connector: PostgresConnector,
    sql: str,
    params: Optional[Mapping[str, Any]] = None,
) -> Optional[Mapping[str, Any]]:
    """
    Возвращает один словарь или None.
    """
    async def _op():
        async with session_scope(connector) as s:
            res = await s.execute(text(sql), params or {})
            row = res.mappings().first()
            return dict(row) if row is not None else None

    return await _with_retry(connector, _op, op_name="fetch_one")

# ======================================================================================
# Массовые операции
# ======================================================================================

async def bulk_upsert(
    connector: PostgresConnector,
    *,
    table: str,
    rows: Sequence[Mapping[str, Any]],
    conflict_cols: Sequence[str],
    update_cols: Optional[Sequence[str]] = None,
) -> int:
    """
    Универсальный UPSERT.
    - table: безопасное имя таблицы (schema.table допускается).
    - rows: список словарей одинаковой структуры.
    - conflict_cols: по каким колонкам выявляется конфликт.
    - update_cols: какие колонки обновлять при конфликте; если None — все, кроме конфликтных.
    Возвращает количество вставленных/обновленных строк (оценочно).
    """
    if not rows:
        return 0

    if not _RE_SAFE_IDENT.match(table):
        raise ValueError("Unsafe table identifier")

    cols: List[str] = list(rows[0].keys())
    if not cols:
        return 0

    for c in cols + list(conflict_cols):
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", c):
            raise ValueError(f"Unsafe column: {c}")

    if update_cols is None:
        update_cols = [c for c in cols if c not in conflict_cols]

    placeholders = ", ".join([f":{c}" for c in cols])
    columns_sql = ", ".join([f'"{c}"' for c in cols])
    conflict_sql = ", ".join([f'"{c}"' for c in conflict_cols])
    set_sql = ", ".join([f'"{c}" = EXCLUDED."{c}"' for c in update_cols])

    sql = f"""
    INSERT INTO {table} ({columns_sql})
    VALUES ({placeholders})
    ON CONFLICT ({conflict_sql})
    DO UPDATE SET {set_sql}
    """

    # batched execution
    async def _op():
        async with session_scope(connector) as s:
            total = 0
            # Чанкование для больших наборов
            CHUNK = 1000
            for i in range(0, len(rows), CHUNK):
                chunk = rows[i : i + CHUNK]
                await s.execute(text(sql), chunk)  # executemany
                total += len(chunk)
            return total

    return await _with_retry(connector, _op, op_name="bulk_upsert")

async def copy_into(
    connector: PostgresConnector,
    *,
    table: str,
    rows: Iterable[Sequence[Any]],
    columns: Sequence[str],
    truncate: bool = False,
) -> int:
    """
    Быстрая массовая загрузка через сырой доступ к asyncpg: COPY TABLE (columns) FROM STDIN (FORMAT csv).
    - rows: итератор последовательностей (в том порядке, что в `columns`)
    Требует драйвер asyncpg (используется по умолчанию в DSN).
    """
    if not _RE_SAFE_IDENT.match(table):
        raise ValueError("Unsafe table identifier")
    for c in columns:
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", c):
            raise ValueError(f"Unsafe column: {c}")

    cols_sql = ", ".join([f'"{c}"' for c in columns])

    async def _op():
        async with connector.engine.begin() as conn:
            # по желанию чистим таблицу в рамках той же транзакции
            if truncate:
                await conn.execute(text(f"TRUNCATE TABLE {table}"))

            raw = await conn.get_raw_connection()
            # raw — это asyncpg.Connection
            # Используем COPY в CSV (быстрее всего) с безопасным экранированием
            copied = 0
            writer = await raw.copy_from_table(table, columns=list(columns), format="csv")
            try:
                # Формируем CSV‑строки самостоятельно, чтобы не тратить память на буферизацию
                import csv
                import io

                buf = io.StringIO()
                csv_writer = csv.writer(buf, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)

                for row in rows:
                    buf.seek(0)
                    buf.truncate(0)
                    csv_writer.writerow(list(row))
                    await writer.write(buf.getvalue().encode("utf-8"))
                    copied += 1
            finally:
                await writer.finish()
            return copied

    return await _with_retry(connector, _op, op_name="copy_into")

# ======================================================================================
# Health‑check
# ======================================================================================

async def ping(connector: PostgresConnector) -> bool:
    """
    Проверяет доступность БД и возвращает True/False. Не бросает исключений.
    """
    try:
        row = await fetch_one(connector, "SELECT 1 AS ok")
        return bool(row and row.get("ok") == 1)
    except Exception:
        logger.exception("pg.ping.failed")
        return False

# ======================================================================================
# Утилиты высокого уровня
# ======================================================================================

async def with_transaction(
    connector: PostgresConnector,
    func: Callable[[AsyncSession], Any],
    *,
    read_only: Optional[bool] = None,
) -> Any:
    """
    Выполняет переданную корутину в транзакции и делает retry при временных ошибках блокировок/сетевых сбоях.
    """
    async def _op():
        async with session_scope(connector, read_only=read_only) as s:
            return await func(s)

    return await _with_retry(connector, _op, op_name="tx")

# ======================================================================================
# Пример самостоятельного запуска: python -m datafabric.connectors.postgres
# ======================================================================================

async def _demo() -> None:
    # DSN можно брать из вашего datafabric.settings.get_settings().pg_async_dsn
    dsn = os.getenv("PG_ASYNC_DSN", "postgresql+asyncpg://postgres:postgres@localhost:5432/postgres?sslmode=disable")
    cfg = PostgresConfig(dsn=dsn, echo=False)
    conn = PostgresConnector.create(cfg)

    ok = await ping(conn)
    print("ping:", ok)

    await execute(conn, "CREATE TABLE IF NOT EXISTS df_demo (id bigint primary key, payload jsonb not null)")
    # upsert
    rows = [{"id": i, "payload": {"v": i}} for i in range(1, 6)]
    n = await bulk_upsert(conn, table="df_demo", rows=rows, conflict_cols=["id"])
    print("upserted:", n)

    data = await fetch_all(conn, "SELECT id, payload FROM df_demo ORDER BY id")
    print("rows:", data[:2], "...")

    # COPY (быстро)
    gen = ([i, {"v": i * 10}] for i in range(6, 1006))
    await copy_into(conn, table="df_demo", rows=((r[0], r[1]) for r in gen), columns=["id", "payload"])

    await conn.close()

if __name__ == "__main__":
    # Локальный тест (требуется запущенный Postgres и драйвер asyncpg)
    asyncio.run(_demo())
