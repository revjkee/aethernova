# datafabric-core/datafabric/storage/warehouse/snowflake_adapter.py
from __future__ import annotations

import concurrent.futures
import contextlib
import dataclasses
import json
import logging
import os
import random
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

import snowflake.connector
from snowflake.connector import ProgrammingError, OperationalError, DatabaseError
from snowflake.connector.cursor import SnowflakeCursor

try:
    # write_pandas ускоряет массовую загрузку из pandas.DataFrame (опционально)
    from snowflake.connector.pandas_tools import write_pandas as _write_pandas  # type: ignore
    HAS_PANDAS = True
except Exception:
    HAS_PANDAS = False

logger = logging.getLogger("datafabric.snowflake")

# ======================================================================================
# Метрики (минимальный интерфейс)
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
class SnowflakeConfig:
    account: str
    user: str
    # Ровно один из следующих способов аутентификации:
    password: Optional[str] = None                 # пароли
    authenticator: Optional[str] = None            # например "externalbrowser" / "oauth"
    token: Optional[str] = None                    # OAuth/JWT
    private_key_path: Optional[str] = None         # RSA PKCS8
    private_key_passphrase: Optional[str] = None

    role: Optional[str] = None
    warehouse: Optional[str] = None
    database: Optional[str] = None
    schema: Optional[str] = None

    client_session_keep_alive: bool = True
    login_timeout: int = 20
    network_timeout: int = 60
    statement_timeout_s: int = 300

    # Поведение приложения
    autocommit: bool = False
    query_tag: str = "datafabric-core"
    application: str = "datafabric-core"
    timezone: Optional[str] = "UTC"

    # Ретраи
    retry_max_attempts: int = 6
    retry_base_delay_ms: int = 200
    retry_max_delay_ms: int = 8000

# ======================================================================================
# Утилиты
# ======================================================================================

_TRANSIENT_SQLSTATES = {
    # Подмножество транзиентных условий Snowflake/ODBC
    "390100",  # connection lost
    "390101",  # connection reset
    "390111",  # HTTP 5xx from service
    "390112",  # HTTP 403/timeout
    "57P01",   # admin_shutdown (совместимость)
    "57014",   # cancel/timeout
    "53200",   # out_of_memory/ресурс временно недоступен
}

def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, (OperationalError,)):
        return True
    if isinstance(exc, (ProgrammingError, DatabaseError)):
        sqlstate = getattr(exc, "sqlstate", None)
        if sqlstate and str(sqlstate) in _TRANSIENT_SQLSTATES:
            return True
        # Иногда код лежит в .errno/.msg от HTTP шлюза
        msg = str(exc).lower()
        if any(x in msg for x in ("timeout", "temporarily unavailable", "service busy", "connection is closed")):
            return True
    return False

def _jit_backoff(attempt: int, base_ms: int, max_ms: int) -> float:
    exp = min(max_ms, base_ms * (2 ** attempt))
    return random.uniform(base_ms, exp) / 1000.0

# ======================================================================================
# Сеанс и адаптер
# ======================================================================================

class _SyncConnection:
    """
    Потокобезопасная обёртка над snowflake.connector.connect() с хранением коннекта.
    Важно: курсоры Snowflake не потокобезопасны — используем их строго внутри worker‑потока.
    """
    def __init__(self, cfg: SnowflakeConfig):
        self.cfg = cfg
        self._conn = None
        self._lock = threading.RLock()

    def connect(self):
        with self._lock:
            if self._conn is not None:
                return self._conn

            params: Dict[str, Any] = dict(
                account=self.cfg.account,
                user=self.cfg.user,
                login_timeout=self.cfg.login_timeout,
                network_timeout=self.cfg.network_timeout,
                client_session_keep_alive=self.cfg.client_session_keep_alive,
                autocommit=self.cfg.autocommit,
                application=self.cfg.application,
                session_parameters={
                    "QUERY_TAG": self.cfg.query_tag,
                    "TIMEZONE": self.cfg.timezone or "UTC",
                    "STATEMENT_TIMEOUT_IN_SECONDS": self.cfg.statement_timeout_s,
                },
            )

            # Аутентификация
            if self.cfg.token:
                params["token"] = self.cfg.token
                params["authenticator"] = "oauth"
            elif self.cfg.authenticator:
                params["authenticator"] = self.cfg.authenticator
                if self.cfg.password:
                    params["password"] = self.cfg.password
            elif self.cfg.private_key_path:
                from cryptography.hazmat.backends import default_backend  # type: ignore
                from cryptography.hazmat.primitives import serialization  # type: ignore
                with open(self.cfg.private_key_path, "rb") as f:
                    pkey = serialization.load_pem_private_key(
                        f.read(),
                        password=(self.cfg.private_key_passphrase.encode() if self.cfg.private_key_passphrase else None),
                        backend=default_backend(),
                    )
                pkb = pkey.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                params["private_key"] = pkb
            else:
                params["password"] = self.cfg.password or ""

            # Контекст
            if self.cfg.role:
                params["role"] = self.cfg.role
            if self.cfg.warehouse:
                params["warehouse"] = self.cfg.warehouse
            if self.cfg.database:
                params["database"] = self.cfg.database
            if self.cfg.schema:
                params["schema"] = self.cfg.schema

            self._conn = snowflake.connector.connect(**params)
            return self._conn

    def close(self):
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                finally:
                    self._conn = None

@dataclasses.dataclass
class SnowflakeAdapter:
    cfg: SnowflakeConfig
    metrics: MetricsSink = dataclasses.field(default_factory=NullMetrics)
    _sync: _SyncConnection = dataclasses.field(init=False)
    _pool: concurrent.futures.ThreadPoolExecutor = dataclasses.field(init=False)

    @classmethod
    def create(cls, cfg: SnowflakeConfig, metrics: Optional[MetricsSink] = None, max_workers: int = 4) -> "SnowflakeAdapter":
        inst = cls(cfg=cfg, metrics=metrics or NullMetrics())  # type: ignore
        inst._sync = _SyncConnection(cfg)
        inst._pool = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="sfw")
        return inst

    # ----------------------- lifecycle -----------------------

    def close(self) -> None:
        self._sync.close()
        self._pool.shutdown(wait=True)
        # метрику можно отправить из фонового цикла, здесь просто best‑effort

    # ----------------------- core exec with retry -----------------------

    def _with_retry(self, fn: Callable[[], Any], op: str) -> Any:
        attempt = 0
        while True:
            t0 = time.monotonic()
            try:
                res = fn()
                # метрика best‑effort (синхронно)
                dt = (time.monotonic() - t0) * 1000.0
                try:
                    # не await — адаптер синхронный внутри
                    import asyncio
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        loop.create_task(self.metrics.observe(f"snowflake.{op}.ms", dt))  # fire-and-forget
                except Exception:
                    pass
                return res
            except Exception as e:
                if not _is_retryable(e) or attempt >= self.cfg.retry_max_attempts:
                    try:
                        import asyncio
                        loop = asyncio.get_event_loop()
                        if loop.is_running():
                            loop.create_task(self.metrics.incr(f"snowflake.{op}.error"))
                    except Exception:
                        pass
                    raise
                # retry
                try:
                    import asyncio
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        loop.create_task(self.metrics.incr(f"snowflake.{op}.retry"))
                except Exception:
                    pass
                time.sleep(_jit_backoff(attempt, self.cfg.retry_base_delay_ms, self.cfg.retry_max_delay_ms))
                attempt += 1

    # ----------------------- public API -----------------------

    def execute(self, sql: str, params: Optional[Union[Sequence[Any], Mapping[str, Any]]] = None) -> int:
        """
        DDL/DML, возвращает rowcount. Использует текущий контекст (WH/DB/SCHEMA/ROLE).
        """
        def _op():
            conn = self._sync.connect()
            with conn.cursor() as cur:  # type: SnowflakeCursor
                cur.execute(sql, params or None)
                return int(cur.rowcount if cur.rowcount is not None else 0)

        return self._with_retry(_op, "execute")

    def fetch_all(self, sql: str, params: Optional[Union[Sequence[Any], Mapping[str, Any]]] = None) -> List[Mapping[str, Any]]:
        """
        Возвращает списком словари.
        """
        def _op():
            conn = self._sync.connect()
            with conn.cursor(snowflake.connector.DictCursor) as cur:
                cur.execute(sql, params or None)
                return [dict(r) for r in cur.fetchall()]

        return self._with_retry(_op, "fetch_all")

    def fetch_one(self, sql: str, params: Optional[Union[Sequence[Any], Mapping[str, Any]]] = None) -> Optional[Mapping[str, Any]]:
        def _op():
            conn = self._sync.connect()
            with conn.cursor(snowflake.connector.DictCursor) as cur:
                cur.execute(sql, params or None)
                row = cur.fetchone()
                return dict(row) if row is not None else None

        return self._with_retry(_op, "fetch_one")

    # ----------------------- async wrappers -----------------------

    async def aexecute(self, sql: str, params: Optional[Union[Sequence[Any], Mapping[str, Any]]] = None) -> int:
        import asyncio
        return await asyncio.get_running_loop().run_in_executor(self._pool, self.execute, sql, params)

    async def afetch_all(self, sql: str, params: Optional[Union[Sequence[Any], Mapping[str, Any]]] = None) -> List[Mapping[str, Any]]:
        import asyncio
        return await asyncio.get_running_loop().run_in_executor(self._pool, self.fetch_all, sql, params)

    async def afetch_one(self, sql: str, params: Optional[Union[Sequence[Any], Mapping[str, Any]]] = None) -> Optional[Mapping[str, Any]]:
        import asyncio
        return await asyncio.get_running_loop().run_in_executor(self._pool, self.fetch_one, sql, params)

    # ----------------------- transactions -----------------------

    @contextlib.contextmanager
    def transaction(self):
        """
        Явная транзакция (автокоммит должен быть False).
        """
        conn = self._sync.connect()
        try:
            yield
            conn.commit()
        except Exception:
            with contextlib.suppress(Exception):
                conn.rollback()
            raise

    # ----------------------- context switchers -----------------------

    def use_context(
        self,
        *,
        warehouse: Optional[str] = None,
        database: Optional[str] = None,
        schema: Optional[str] = None,
        role: Optional[str] = None,
    ) -> None:
        """
        Безопасно переключает контекст (если аргумент None — пропускается).
        """
        if role:
            self.execute(f'USE ROLE "{role}"')
        if warehouse:
            self.execute(f'USE WAREHOUSE "{warehouse}"')
        if database:
            self.execute(f'USE DATABASE "{database}"')
        if schema:
            self.execute(f'USE SCHEMA "{schema}"')

    # ----------------------- bulk loading -----------------------

    def copy_into_table_from_stage(
        self,
        *,
        table: str,
        stage: str,
        pattern: Optional[str] = None,
        file_format: str = "TYPE = JSON",
        on_error: str = "ABORT_STATEMENT",
        purge: bool = False,
        force: bool = False,
    ) -> int:
        """
        COPY INTO <table> FROM @<stage> PATTERN='...' FILE_FORMAT=(...) ...
        Возвращает количество успешно загруженных файлов (оценочно).
        """
        patt = f" PATTERN='{pattern}'" if pattern else ""
        opts = f" FILE_FORMAT=({file_format}) ON_ERROR={on_error} PURGE={'TRUE' if purge else 'FALSE'} FORCE={'TRUE' if force else 'FALSE'}"
        sql = f"COPY INTO {table} FROM @{stage}{patt}{opts}"
        def _op():
            conn = self._sync.connect()
            with conn.cursor(snowflake.connector.DictCursor) as cur:
                cur.execute(sql)
                rows = cur.fetchall() or []
                # rows содержат статус по каждому файлу
                loaded = sum(1 for r in rows if str(r.get("STATUS", "")).upper() == "LOADED")
                return int(loaded)
        return self._with_retry(_op, "copy_into")

    def put_file_to_stage(
        self,
        *,
        local_path: Union[str, Path],
        stage: str,
        dest_path: Optional[str] = None,
        auto_compress: bool = False,
        overwrite: bool = True,
        parallel: int = 4,
    ) -> int:
        """
        PUT file://... @stage/path AUTO_COMPRESS=TRUE/FALSE OVERWRITE=TRUE/FALSE
        Возвращает число загруженных файлов.
        """
        lp = Path(local_path).absolute()
        if not lp.exists():
            raise FileNotFoundError(lp)
        dst = f"@{stage}/{dest_path.strip('/')}" if dest_path else f"@{stage}"
        auto = "TRUE" if auto_compress else "FALSE"
        over = "TRUE" if overwrite else "FALSE"
        sql = f"PUT file://{lp.as_posix()} {dst} AUTO_COMPRESS={auto} OVERWRITE={over} PARALLEL={int(max(1, parallel))}"
        def _op():
            conn = self._sync.connect()
            with conn.cursor(snowflake.connector.DictCursor) as cur:
                cur.execute(sql)
                rows = cur.fetchall() or []
                return len(rows)
        return self._with_retry(_op, "put")

    def put_bytes_to_stage(
        self,
        *,
        data: bytes,
        stage: str,
        filename: str,
        dest_path: Optional[str] = None,
        auto_compress: bool = False,
        overwrite: bool = True,
    ) -> int:
        """
        Загрузка байтов в stage через временный файл (официальный драйвер требует локальный путь).
        """
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td) / filename
            tmp.write_bytes(data)
            return self.put_file_to_stage(
                local_path=tmp,
                stage=stage,
                dest_path=dest_path,
                auto_compress=auto_compress,
                overwrite=overwrite,
            )

    def write_pandas(self, df, table: str, *, database: Optional[str] = None, schema: Optional[str] = None, chunk_size: int = 16000) -> int:
        """
        Быстрая загрузка DataFrame. Требует pandas и pyarrow. Возвращает количество загруженных строк.
        """
        if not HAS_PANDAS:
            raise RuntimeError("write_pandas requires pandas support in snowflake-connector")
        conn = self._sync.connect()
        # write_pandas сам создаёт stage и COPY INTO
        success, nchunks, nrows, _ = _write_pandas(
            conn=conn,
            df=df,
            table_name=table,
            database=database or self.cfg.database,
            schema=schema or self.cfg.schema,
            chunk_size=chunk_size,
            auto_create_table=False,
        )
        if not success:
            raise RuntimeError("write_pandas reported failure")
        return int(nrows)

    # ----------------------- upsert/merge helper -----------------------

    def merge_upsert(
        self,
        *,
        table: str,
        src_stage: str,
        src_file_format: str = "TYPE = JSON",
        key_expr: str,
        set_expr: str,
        pattern: Optional[str] = None,
        purge_after: bool = False,
    ) -> int:
        """
        Шаблонный MERGE c источником из stage:
        MERGE INTO <table> t USING (SELECT ... FROM @stage (FILE_FORMAT=... [PATTERN=...])) s
        ON <key_expr>
        WHEN MATCHED THEN UPDATE SET <set_expr>
        WHEN NOT MATCHED THEN INSERT ...
        Возвращает count обновлённых+вставленных строк (оценочно по статусу).
        """
        patt = f" PATTERN='{pattern}'" if pattern else ""
        using = f"(SELECT * FROM @{src_stage} (FILE_FORMAT=({src_file_format}){patt})) s"
        sql = f"""
        MERGE INTO {table} t
        USING {using}
        ON {key_expr}
        WHEN MATCHED THEN UPDATE SET {set_expr}
        WHEN NOT MATCHED THEN INSERT ({set_expr.replace('t.', '').replace('= s.', ', ')})
        """
        # Примечание: последний INERT‑список полей строится эвристически — при необходимости подставляйте явный список.
        def _op():
            conn = self._sync.connect()
            with conn.cursor(snowflake.connector.DictCursor) as cur:
                cur.execute(sql)
                # MERGE возвращает summary строкой, rowcount может быть None
                try:
                    return int(cur.rowcount or 0)
                finally:
                    if purge_after:
                        try:
                            cur.execute(f"REMOVE @{src_stage}")
                        except Exception:
                            pass
        return self._with_retry(_op, "merge")

    # ----------------------- health -----------------------

    def ping(self) -> bool:
        def _op():
            conn = self._sync.connect()
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                return cur.fetchone()[0] == 1
        try:
            return bool(self._with_retry(_op, "ping"))
        except Exception:
            logger.exception("snowflake.ping.failed")
            return False

# ======================================================================================
# Пример использования (ручной тест): python -m datafabric.storage.warehouse.snowflake_adapter
# ======================================================================================

def _demo() -> None:
    cfg = SnowflakeConfig(
        account=os.getenv("SF_ACCOUNT", "your_account"),
        user=os.getenv("SF_USER", "user"),
        password=os.getenv("SF_PASSWORD"),
        role=os.getenv("SF_ROLE"),
        warehouse=os.getenv("SF_WAREHOUSE"),
        database=os.getenv("SF_DATABASE"),
        schema=os.getenv("SF_SCHEMA"),
        query_tag="datafabric-demo",
        statement_timeout_s=120,
    )
    sf = SnowflakeAdapter.create(cfg)
    try:
        print("ping:", sf.ping())
        # Примеры:
        # sf.execute('CREATE TABLE IF NOT EXISTS DEMO (id NUMBER, data VARIANT)')
        # sf.put_bytes_to_stage(data=b'{"id":1,"data":{"x":1}}', stage='~', filename='part-0001.json')
        # sf.copy_into_table_from_stage(table='DEMO', stage='~', file_format='TYPE=JSON')
        # rows = sf.fetch_all('SELECT * FROM DEMO LIMIT 5')
        # print(rows)
        pass
    finally:
        sf.close()

if __name__ == "__main__":
    _demo()
