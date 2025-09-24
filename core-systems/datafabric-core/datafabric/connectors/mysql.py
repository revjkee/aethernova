# datafabric-core/datafabric/connectors/mysql.py
from __future__ import annotations

import asyncio
import contextlib
import os
import random
import re
import ssl as _ssl
import time
from dataclasses import dataclass
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from pydantic import BaseModel, Field, validator

# ===================== Метрики/Трейсинг (протоколы) =====================

class Metrics:
    async def inc(self, name: str, value: int = 1, **labels: str) -> None: ...
    async def observe(self, name: str, value: float, **labels: str) -> None: ...

class Tracer:
    def start_span(self, name: str, **attrs: Any) -> "Span": return Span()

class Span:
    def set_attribute(self, key: str, value: Any) -> None: ...
    def record_exception(self, exc: BaseException) -> None: ...
    def end(self) -> None: ...


# =============================== Конфиг ===============================

class MySQLRetry(BaseModel):
    max_attempts: int = Field(5, ge=1, le=15)
    base_delay_ms: int = Field(100, ge=1)
    max_delay_ms: int = Field(10_000, ge=100)
    jitter_ms: int = Field(200, ge=0)
    exponential_factor: float = Field(2.0, ge=1.0)

class MySQLSSL(BaseModel):
    enabled: bool = Field(False)
    ca_path: Optional[str] = None
    cert_path: Optional[str] = None
    key_path: Optional[str] = None
    verify_mode: str = Field("required", description="none|required|optional")

    @validator("verify_mode")
    def _vm(cls, v: str) -> str:
        v = v.lower()
        if v not in ("none", "required", "optional"):
            raise ValueError("verify_mode must be: none|required|optional")
        return v

class MySQLConfig(BaseModel):
    # DSN и/или хост
    dsn: Optional[str] = Field(None, description="Например: mysql://user:pass@host:3306/db?charset=utf8mb4")
    host: str = Field("127.0.0.1")
    port: int = Field(3306, ge=1, le=65535)
    user: str = Field("root")
    password: str = Field("", repr=False)
    database: Optional[str] = None
    charset: str = Field("utf8mb4")
    collation: Optional[str] = None

    pool_min_size: int = Field(1, ge=1)
    pool_max_size: int = Field(10, ge=1)
    pool_idle_timeout_s: int = Field(300, ge=1)

    connect_timeout_s: int = Field(10, ge=1)
    read_timeout_s: int = Field(300, ge=1)
    write_timeout_s: int = Field(300, ge=1)

    autocommit_default: bool = Field(False)
    tx_isolation: str = Field("READ COMMITTED")  # или REPEATABLE READ
    sql_mode: str = Field("STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION")

    retries: MySQLRetry = MySQLRetry()
    ssl: MySQLSSL = MySQLSSL()

    max_concurrency: int = Field(32, ge=1, le=256)
    metrics_prefix: str = Field("datafabric_mysql")

    @validator("pool_max_size")
    def _pool(cls, v: int, values: Dict[str, Any]) -> int:
        if "pool_min_size" in values and v < values["pool_min_size"]:
            raise ValueError("pool_max_size must be >= pool_min_size")
        return v


# ============================ Исключения ==============================

class MySQLError(Exception): ...
class MySQLConfigError(MySQLError): ...
class MySQLTransientError(MySQLError): ...
class MySQLNonRetryableError(MySQLError): ...


# ============================ Драйверы (опционально) ==================

_async_driver = None  # "asyncmy" | "aiomysql" | None
_sync_driver = None   # "mysql.connector" | "pymysql"

try:  # asyncmy быстрее и корректно async
    import asyncmy  # type: ignore
    from asyncmy import Pool as _AsyncPool  # type: ignore
    _async_driver = "asyncmy"
except Exception:
    try:
        import aiomysql  # type: ignore
        _async_driver = "aiomysql"
    except Exception:
        _async_driver = None

try:
    import mysql.connector  # type: ignore
    _sync_driver = "mysql.connector"
except Exception:
    try:
        import pymysql  # type: ignore
        _sync_driver = "pymysql"
    except Exception:
        _sync_driver = None


# ============================ Вспомогательное =========================

def _compute_backoff(attempt: int, cfg: MySQLRetry) -> float:
    base = cfg.base_delay_ms / 1000.0
    delay = min(base * (cfg.exponential_factor ** (attempt - 1)), cfg.max_delay_ms / 1000.0)
    jitter = (cfg.jitter_ms / 1000.0) * (os.urandom(1)[0] / 255.0) if cfg.jitter_ms > 0 else 0.0
    return delay + jitter

_ID_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_\$]*$")

def _quote_ident(name: str) -> str:
    # минимальный whitelist для идентификаторов
    if not _ID_RE.match(name):
        raise MySQLNonRetryableError(f"Invalid SQL identifier: {name!r}")
    return f"`{name}`"

def _is_transient(err: BaseException) -> bool:
    # Эвристика/коды ошибок MySQL/MariaDB
    # 1205 Lock wait timeout; 1213 Deadlock; 2006 MySQL server has gone away; 2013 Lost connection
    text = str(err)
    markers = ("1205", "1213", "2006", "2013", "Lock wait timeout", "Deadlock found", "gone away", "Lost connection")
    return any(m in text for m in markers)

def _build_ssl_context(cfg: MySQLSSL) -> Optional[_ssl.SSLContext]:
    if not cfg.enabled:
        return None
    ctx = _ssl.create_default_context(cafile=cfg.ca_path) if cfg.ca_path else _ssl.create_default_context()
    if cfg.cert_path and cfg.key_path:
        ctx.load_cert_chain(cfg.cert_path, cfg.key_path)
    if cfg.verify_mode == "none":
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
    elif cfg.verify_mode == "optional":
        ctx.verify_mode = _ssl.CERT_OPTIONAL
    else:
        ctx.verify_mode = _ssl.CERT_REQUIRED
    return ctx


# ============================ Основной класс ==========================

class MySQLConnector:
    """
    Универсальный коннектор MySQL/MariaDB:
    - асинхронный пул (asyncmy/aiomysql), fallback на синхронный драйвер в thread pool
    - безопасные параметризованные запросы
    - транзакции с ретраями на deadlock/timeout
    - стриминговое чтение и батч‑вставки/UPSERT
    """

    def __init__(
        self,
        cfg: MySQLConfig,
        *,
        metrics: Optional[Metrics] = None,
        tracer: Optional[Tracer] = None,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        self.cfg = cfg
        self.metrics = metrics or Metrics()
        self.tracer = tracer or Tracer()
        self.loop = loop or asyncio.get_event_loop()
        self._pool = None
        self._sem = asyncio.Semaphore(cfg.max_concurrency)
        self._ssl_context = _build_ssl_context(cfg.ssl)

    # -------------------------- Lifecycle --------------------------

    async def __aenter__(self) -> "MySQLConnector":
        await self._ensure_pool()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def _ensure_pool(self) -> None:
        if self._pool is not None:
            return
        span = self.tracer.start_span("mysql.ensure_pool", driver=_async_driver or _sync_driver or "none")
        t0 = time.perf_counter()
        try:
            if _async_driver == "asyncmy":
                # https://github.com/long2ice/asyncmy
                self._pool = await asyncmy.create_pool(
                    host=self.cfg.host, port=self.cfg.port,
                    user=self.cfg.user, password=self.cfg.password,
                    db=self.cfg.database, autocommit=self.cfg.autocommit_default,
                    minsize=self.cfg.pool_min_size, maxsize=self.cfg.pool_max_size,
                    connect_timeout=self.cfg.connect_timeout_s,
                    read_timeout=self.cfg.read_timeout_s, write_timeout=self.cfg.write_timeout_s,
                    charset=self.cfg.charset, ssl=self._ssl_context,
                )
            elif _async_driver == "aiomysql":
                self._pool = await aiomysql.create_pool(  # type: ignore
                    host=self.cfg.host, port=self.cfg.port,
                    user=self.cfg.user, password=self.cfg.password,
                    db=self.cfg.database, autocommit=self.cfg.autocommit_default,
                    minsize=self.cfg.pool_min_size, maxsize=self.cfg.pool_max_size,
                    connect_timeout=self.cfg.connect_timeout_s,
                    charset=self.cfg.charset, ssl=self._ssl_context,
                )
            else:
                # Синхронный fallback, будем исполнять в thread pool
                self._pool = "_sync"
            # Применим режимы
            await self._apply_session_modes()
        except Exception as e:
            span.record_exception(e)
            raise MySQLError(f"Failed to create MySQL pool: {e}") from e
        finally:
            await self.metrics.observe(f"{self.cfg.metrics_prefix}_pool_init_seconds", time.perf_counter() - t0)
            span.end()

    async def close(self) -> None:
        if self._pool is None:
            return
        if _async_driver == "asyncmy":
            with contextlib.suppress(Exception):
                self._pool.close()
                await self._pool.wait_closed()
        elif _async_driver == "aiomysql":
            with contextlib.suppress(Exception):
                self._pool.close()  # type: ignore
                await self._pool.wait_closed()  # type: ignore
        self._pool = None

    # -------------------------- Health/Ready --------------------------

    async def ping(self) -> bool:
        try:
            await self._ensure_pool()
            await self.execute("/*ping*/ SELECT 1")
            return True
        except Exception:
            return False

    # -------------------------- Вспомогательные низкоуровневые --------------------------

    async def _apply_session_modes(self) -> None:
        try:
            await self.execute(f"SET SESSION TRANSACTION ISOLATION LEVEL {self.cfg.tx_isolation}")
            await self.execute("SET SESSION sql_log_bin = 0")  # безопаснее для миграций/сидов в некоторых средах
            await self.execute("SET SESSION innodb_lock_wait_timeout = 50")
            await self.execute("SET SESSION wait_timeout = 28800")
            if self.cfg.sql_mode:
                await self.execute("SET SESSION sql_mode = %s", (self.cfg.sql_mode,))
            if self.cfg.collation:
                await self.execute("SET SESSION collation_connection = %s", (self.cfg.collation,))
        except Exception:
            # режимы не критичны — не срываем инициализацию
            pass

    def _build_sync_conn(self):
        if _sync_driver == "mysql.connector":
            import mysql.connector  # type: ignore
            kw = dict(
                host=self.cfg.host, port=self.cfg.port, user=self.cfg.user, password=self.cfg.password,
                database=self.cfg.database, autocommit=self.cfg.autocommit_default,
                connection_timeout=self.cfg.connect_timeout_s, charset=self.cfg.charset,
            )
            if self._ssl_context:
                kw["ssl_ca"] = getattr(self.cfg.ssl, "ca_path", None)
                kw["ssl_cert"] = getattr(self.cfg.ssl, "cert_path", None)
                kw["ssl_key"] = getattr(self.cfg.ssl, "key_path", None)
            return mysql.connector.connect(**kw)
        elif _sync_driver == "pymysql":
            import pymysql  # type: ignore
            kw = dict(
                host=self.cfg.host, port=self.cfg.port, user=self.cfg.user, password=self.cfg.password,
                database=self.cfg.database, autocommit=self.cfg.autocommit_default, charset=self.cfg.charset,
                connect_timeout=self.cfg.connect_timeout_s,
                read_timeout=self.cfg.read_timeout_s, write_timeout=self.cfg.write_timeout_s,
                ssl=self._ssl_context,
            )
            return pymysql.connect(**kw)
        raise MySQLConfigError("No available MySQL driver (asyncmy/aiomysql/mysql.connector/pymysql)")

    # Унифицированный вызов SQL с ретраями
    async def _call_with_retry(self, fn: Callable[[], Awaitable[Any]], op_name: str) -> Any:
        attempt = 1
        t0 = time.perf_counter()
        span = self.tracer.start_span(f"mysql.{op_name}")
        try:
            while True:
                try:
                    async with self._sem:
                        res = await fn()
                    await self.metrics.inc(f"{self.cfg.metrics_prefix}_{op_name}_total")
                    return res
                except Exception as e:
                    transient = _is_transient(e)
                    if not transient or attempt >= self.cfg.retries.max_attempts:
                        span.record_exception(e)
                        raise
                    delay = _compute_backoff(attempt, self.cfg.retries)
                    attempt += 1
                    await asyncio.sleep(delay)
        finally:
            await self.metrics.observe(f"{self.cfg.metrics_prefix}_{op_name}_seconds", time.perf_counter() - t0)
            span.end()

    # -------------------------- Публичные операции --------------------------

    async def execute(self, sql: str, params: Optional[Sequence[Any]] = None) -> int:
        """
        DDL/DML без результата. Возвращает число затронутых строк.
        """
        params = tuple(params or ())
        async def _run():
            if _async_driver == "asyncmy":
                async with self._pool.acquire() as conn:  # type: ignore
                    async with conn.cursor() as cur:
                        await cur.execute(sql, params)
                        return cur.rowcount or 0
            elif _async_driver == "aiomysql":
                async with self._pool.acquire() as conn:  # type: ignore
                    async with conn.cursor() as cur:  # type: ignore
                        await cur.execute(sql, params)
                        return cur.rowcount or 0
            else:
                def _sync():
                    conn = self._build_sync_conn()
                    try:
                        cur = conn.cursor()
                        cur.execute(sql, params)
                        affected = cur.rowcount or 0
                        conn.commit()
                        return affected
                    finally:
                        conn.close()
                return await asyncio.to_thread(_sync)
        return await self._call_with_retry(_run, "execute")

    async def fetch_one(self, sql: str, params: Optional[Sequence[Any]] = None) -> Optional[Tuple[Any, ...]]:
        params = tuple(params or ())
        async def _run():
            if _async_driver in ("asyncmy", "aiomysql"):
                async with self._pool.acquire() as conn:  # type: ignore
                    async with conn.cursor() as cur:
                        await cur.execute(sql, params)
                        return await cur.fetchone()
            else:
                def _sync():
                    conn = self._build_sync_conn()
                    try:
                        cur = conn.cursor()
                        cur.execute(sql, params)
                        return cur.fetchone()
                    finally:
                        conn.close()
                return await asyncio.to_thread(_sync)
        return await self._call_with_retry(_run, "fetch_one")

    async def fetch_all(self, sql: str, params: Optional[Sequence[Any]] = None) -> List[Tuple[Any, ...]]:
        params = tuple(params or ())
        async def _run():
            if _async_driver in ("asyncmy", "aiomysql"):
                async with self._pool.acquire() as conn:  # type: ignore
                    async with conn.cursor() as cur:
                        await cur.execute(sql, params)
                        return list(await cur.fetchall())
            else:
                def _sync():
                    conn = self._build_sync_conn()
                    try:
                        cur = conn.cursor()
                        cur.execute(sql, params)
                        return list(cur.fetchall())
                    finally:
                        conn.close()
                return await asyncio.to_thread(_sync)
        return await self._call_with_retry(_run, "fetch_all")

    async def stream_query(self, sql: str, params: Optional[Sequence[Any]] = None, *, arraysize: int = 1000) -> AsyncIterator[Tuple[Any, ...]]:
        """
        Потоковое чтение результата. Для sync‑драйвера чанкуем в thread‑pool.
        """
        params = tuple(params or ())
        if _async_driver == "asyncmy":
            async def _gen():
                async with self._pool.acquire() as conn:  # type: ignore
                    async with conn.cursor() as cur:
                        await cur.execute(sql, params)
                        while True:
                            rows = await cur.fetchmany(arraysize)
                            if not rows:
                                break
                            for r in rows:
                                yield r
            async for r in self._call_stream(_gen, "stream_query"):
                yield r
        elif _async_driver == "aiomysql":
            async def _gen():
                async with self._pool.acquire() as conn:  # type: ignore
                    async with conn.cursor() as cur:  # type: ignore
                        await cur.execute(sql, params)
                        while True:
                            rows = await cur.fetchmany(arraysize)
                            if not rows:
                                break
                            for r in rows:
                                yield r
            async for r in self._call_stream(_gen, "stream_query"):
                yield r
        else:
            def _sync_fetch() -> List[Tuple[Any, ...]]:
                conn = self._build_sync_conn()
                try:
                    cur = conn.cursor()
                    cur.execute(sql, params)
                    out: List[Tuple[Any, ...]] = []
                    while True:
                        rows = cur.fetchmany(arraysize)
                        if not rows:
                            break
                        out.extend(rows)
                    return out
                finally:
                    conn.close()
            # для синхронного — возвращаем пачкой
            rows = await asyncio.to_thread(_sync_fetch)
            for r in rows:
                yield r

    async def _call_stream(self, gen_fn: Callable[[], AsyncIterator[Tuple[Any, ...]]], op_name: str) -> AsyncIterator[Tuple[Any, ...]]:
        attempt = 1
        span = self.tracer.start_span(f"mysql.{op_name}")
        try:
            while True:
                try:
                    async with self._sem:
                        async for row in gen_fn():
                            yield row
                    await self.metrics.inc(f"{self.cfg.metrics_prefix}_{op_name}_total")
                    return
                except Exception as e:
                    if not _is_transient(e) or attempt >= self.cfg.retries.max_attempts:
                        span.record_exception(e)
                        raise
                    await asyncio.sleep(_compute_backoff(attempt, self.cfg.retries))
                    attempt += 1
        finally:
            span.end()

    async def executemany(self, sql: str, seq_params: Sequence[Sequence[Any]], *, chunk_size: int = 1000) -> int:
        """
        Безопасный executemany с чанкингом.
        """
        total = 0
        for i in range(0, len(seq_params), chunk_size):
            chunk = [tuple(p) for p in seq_params[i : i + chunk_size]]
            async def _run():
                if _async_driver in ("asyncmy", "aiomysql"):
                    async with self._pool.acquire() as conn:  # type: ignore
                        async with conn.cursor() as cur:
                            await cur.executemany(sql, chunk)
                            return cur.rowcount or 0
                else:
                    def _sync():
                        conn = self._build_sync_conn()
                        try:
                            cur = conn.cursor()
                            cur.executemany(sql, chunk)
                            affected = cur.rowcount or 0
                            conn.commit()
                            return affected
                        finally:
                            conn.close()
                    return await asyncio.to_thread(_sync)
            total += await self._call_with_retry(_run, "executemany")
        return total

    async def bulk_insert(
        self,
        table: str,
        columns: Sequence[str],
        rows: Sequence[Sequence[Any]],
        *,
        on_duplicate_update: Optional[Sequence[str]] = None,
        chunk_size: int = 1000,
    ) -> int:
        """
        Вставка батчами с опциональным ON DUPLICATE KEY UPDATE.
        """
        if not columns:
            raise MySQLNonRetryableError("columns cannot be empty")
        cols_q = ", ".join(_quote_ident(c) for c in columns)
        placeholders = "(" + ", ".join(["%s"] * len(columns)) + ")"

        if on_duplicate_update:
            updates = ", ".join(f"{_quote_ident(c)}=VALUES({_quote_ident(c)})" for c in on_duplicate_update)
            suffix = f" ON DUPLICATE KEY UPDATE {updates}"
        else:
            suffix = ""

        sql = f"INSERT INTO {_quote_ident(table)} ({cols_q}) VALUES {placeholders} {suffix}"

        total = 0
        for i in range(0, len(rows), chunk_size):
            chunk = [tuple(r) for r in rows[i : i + chunk_size]]
            # executemany требует sql без многократных placeholders — корректно
            total += await self.executemany(sql, chunk, chunk_size=len(chunk))
        return total

    async def upsert(
        self,
        table: str,
        key_columns: Sequence[str],
        update_columns: Sequence[str],
        rows: Sequence[Dict[str, Any]],
        *,
        chunk_size: int = 1000,
    ) -> int:
        """
        Высокоуровневый UPSERT по словарям: key_columns задают уникальный ключ, update_columns — поля обновления.
        """
        if not rows:
            return 0
        all_cols = list({c for r in rows for c in r.keys()})
        # гарантируем порядок: сначала ключевые, потом остальные
        ordered_cols = list(dict.fromkeys(list(key_columns) + [c for c in all_cols if c not in key_columns]))
        values = [[r.get(c) for c in ordered_cols] for r in rows]
        return await self.bulk_insert(
            table=table,
            columns=ordered_cols,
            rows=values,
            on_duplicate_update=update_columns,
            chunk_size=chunk_size,
        )

    # -------------------------- Транзакции --------------------------

    class _Tx:
        def __init__(self, connector: "MySQLConnector") -> None:
            self.c = connector
            self._conn = None
            self._cur = None
            self._is_async = _async_driver in ("asyncmy", "aiomysql")

        async def __aenter__(self) -> "MySQLConnector._Tx":
            await self.c._ensure_pool()
            if self._is_async:
                self._conn = await self.c._pool.acquire()  # type: ignore
                self._cur = await self._conn.cursor()
                await self._cur.execute("BEGIN")
            else:
                self._conn = await asyncio.to_thread(self.c._build_sync_conn)
                self._cur = self._conn.cursor()
                self._cur.execute("BEGIN")
            return self

        async def execute(self, sql: str, params: Optional[Sequence[Any]] = None) -> int:
            params = tuple(params or ())
            if self._is_async:
                await self._cur.execute(sql, params)
                return self._cur.rowcount or 0
            else:
                return await asyncio.to_thread(lambda: self._cur.execute(sql, params) or (self._cur.rowcount or 0))

        async def fetch_one(self, sql: str, params: Optional[Sequence[Any]] = None) -> Optional[Tuple[Any, ...]]:
            params = tuple(params or ())
            if self._is_async:
                await self._cur.execute(sql, params)
                return await self._cur.fetchone()
            else:
                def _run():
                    self._cur.execute(sql, params)
                    return self._cur.fetchone()
                return await asyncio.to_thread(_run)

        async def fetch_all(self, sql: str, params: Optional[Sequence[Any]] = None) -> List[Tuple[Any, ...]]:
            params = tuple(params or ())
            if self._is_async:
                await self._cur.execute(sql, params)
                return list(await self._cur.fetchall())
            else:
                def _run():
                    self._cur.execute(sql, params)
                    return list(self._cur.fetchall())
                return await asyncio.to_thread(_run)

        async def __aexit__(self, exc_type, exc, tb) -> None:
            try:
                if exc:
                    if self._is_async:
                        await self._conn.rollback()
                    else:
                        await asyncio.to_thread(self._conn.rollback)
                else:
                    if self._is_async:
                        await self._conn.commit()
                    else:
                        await asyncio.to_thread(self._conn.commit)
            finally:
                if self._is_async:
                    with contextlib.suppress(Exception):
                        await self._cur.close()
                        self.c._pool.release(self._conn)  # type: ignore
                else:
                    with contextlib.suppress(Exception):
                        self._cur.close()
                        self._conn.close()

    async def transaction(self, fn: Callable[["MySQLConnector._Tx"], Awaitable[Any]], *, name: str = "tx") -> Any:
        """
        Обёртка транзакции с ретраями (deadlock/timeout).
        """
        attempt = 1
        span = self.tracer.start_span(f"mysql.{name}")
        t0 = time.perf_counter()
        try:
            while True:
                try:
                    async with self._Tx(self) as tx:
                        res = await fn(tx)
                    await self.metrics.inc(f"{self.cfg.metrics_prefix}_transaction_total")
                    return res
                except Exception as e:
                    if not _is_transient(e) or attempt >= self.cfg.retries.max_attempts:
                        span.record_exception(e)
                        raise
                    await asyncio.sleep(_compute_backoff(attempt, self.cfg.retries))
                    attempt += 1
        finally:
            await self.metrics.observe(f"{self.cfg.metrics_prefix}_transaction_seconds", time.perf_counter() - t0)
            span.end()

    # -------------------------- Миграции/схема --------------------------

    async def ensure_schema_version(self) -> None:
        """
        Создает таблицу служебной версии схемы (если нет) и удерживает только одну запись (id=1).
        """
        await self.execute("""
            CREATE TABLE IF NOT EXISTS _schema_version (
                id TINYINT PRIMARY KEY,
                version INT NOT NULL,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        row = await self.fetch_one("SELECT version FROM _schema_version WHERE id=1")
        if row is None:
            await self.execute("INSERT INTO _schema_version (id, version) VALUES (1, %s)", (1,))

    async def set_schema_version(self, version: int) -> None:
        await self.execute("UPDATE _schema_version SET version=%s WHERE id=1", (version,))

    async def get_schema_version(self) -> int:
        row = await self.fetch_one("SELECT version FROM _schema_version WHERE id=1")
        return int(row[0]) if row else 0
