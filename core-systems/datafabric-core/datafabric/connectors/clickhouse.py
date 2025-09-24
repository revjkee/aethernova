# datafabric-core/datafabric/connectors/clickhouse.py
"""
Промышленный коннектор ClickHouse для DataFabric.

Особенности:
- Библиотека: clickhouse-connect (sync/async клиенты).
- Конфиг через pydantic: TLS, аутентификация, база, сессия, настройки.
- Ретраи с экспоненциальной задержкой и джиттером на идемпотентные операции (SELECT/DDL).
- Таймауты connect/read/write, query_id, query_settings на запрос.
- Параметризованные запросы, безопасная подстановка.
- Вставки: батч (insert_rows), колоночные, semi‑stream (итератор).
- Async и Sync API с единым фасадом.
- Метрики Prometheus: счётчики операций, ошибок, латентности, объёма вставок/выборок.
- OpenTelemetry: кастомные спаны вокруг запросов.
- Идемпотентные миграции (simple registry table), health‑check, graceful close.
- Опциональная интеграция с pandas/pyarrow (если установлены).

Зависимости:
- clickhouse-connect >= 0.7
- pydantic >= 2
Опционально:
- prometheus-client
- opentelemetry-sdk (+ otlp-exporter)
- pandas/pyarrow (для удобства df/arrow)
"""

from __future__ import annotations

import os
import time
import random
import logging
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence, Optional, Dict, List, Tuple

try:
    from pydantic import BaseModel, Field, ValidationError, field_validator
except Exception as ex:  # pragma: no cover
    raise RuntimeError("pydantic>=2 is required") from ex

# ClickHouse client (sync/async)
try:
    import clickhouse_connect  # type: ignore
    from clickhouse_connect.driver.exceptions import ClickHouseError  # type: ignore
    _CH_AVAILABLE = True
except Exception as ex:  # pragma: no cover
    _CH_AVAILABLE = False
    ClickHouseError = Exception  # type: ignore

# Prometheus (опционально)
try:
    from prometheus_client import Counter, Histogram  # type: ignore
    _PROM = True
except Exception:  # pragma: no cover
    _PROM = False
    Counter = Histogram = None  # type: ignore

# OpenTelemetry (опционально)
try:
    from opentelemetry import trace  # type: ignore
    _TRACER = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _TRACER = None


# =========================
# Конфигурация
# =========================

class ClickHouseConfig(BaseModel):
    host: str = Field(default="localhost")
    port: int = Field(default=8443)                # 8443 (HTTPS) / 8123 (HTTP) / 9440 (native TLS) — зависит от deployment
    username: str = Field(default="default")
    password: str = Field(default="")
    database: str = Field(default="default")
    # Протокол: HTTP (рекомендуется для clickhouse-connect) + TLS
    secure: bool = Field(default=True, description="TLS для HTTP клиента")
    verify: bool = Field(default=True, description="Проверка сертификата TLS")
    client_name: str = Field(default="datafabric-clickhouse")
    # Таймауты
    connect_timeout: float = Field(default=5.0)
    send_receive_timeout: float = Field(default=60.0)
    # Ретраи
    max_retries: int = Field(default=5)
    base_backoff_s: float = Field(default=0.2)
    max_backoff_s: float = Field(default=5.0)
    # Сессии и айди запросов
    session_id: Optional[str] = Field(default=None)
    # Доп. настройки ClickHouse (per-request будут объединяться)
    settings: Dict[str, Any] = Field(default_factory=lambda: {"max_result_rows": 0})
    # Сжатие HTTP
    compression: str = Field(default="gzip")  # gzip|lz4|none
    # Размер батча вставки
    insert_batch_size: int = Field(default=10000)

    @field_validator("compression")
    @classmethod
    def _chk_compression(cls, v: str) -> str:
        v = v.lower()
        if v not in ("gzip", "lz4", "none"):
            raise ValueError("compression must be gzip|lz4|none")
        return v

    @classmethod
    def from_env(cls) -> "ClickHouseConfig":
        return cls(
            host=os.getenv("CH_HOST", "localhost"),
            port=int(os.getenv("CH_PORT", "8443")),
            username=os.getenv("CH_USER", "default"),
            password=os.getenv("CH_PASS", ""),
            database=os.getenv("CH_DB", "default"),
            secure=os.getenv("CH_SECURE", "true").lower() == "true",
            verify=os.getenv("CH_VERIFY", "true").lower() == "true",
            client_name=os.getenv("CH_CLIENT_NAME", "datafabric-clickhouse"),
            connect_timeout=float(os.getenv("CH_CONNECT_TIMEOUT", "5")),
            send_receive_timeout=float(os.getenv("CH_RW_TIMEOUT", "60")),
            max_retries=int(os.getenv("CH_MAX_RETRIES", "5")),
            base_backoff_s=float(os.getenv("CH_BASE_BACKOFF", "0.2")),
            max_backoff_s=float(os.getenv("CH_MAX_BACKOFF", "5.0")),
            session_id=os.getenv("CH_SESSION_ID") or None,
            compression=os.getenv("CH_COMPRESSION", "gzip"),
            insert_batch_size=int(os.getenv("CH_INSERT_BATCH", "10000")),
        )


# =========================
# Метрики
# =========================

def _build_metrics(ns: str = "datafabric_clickhouse") -> Dict[str, Any]:
    if not _PROM:
        return {}
    labels = ("db", "op")
    return {
        "ops": Counter(f"{ns}_ops_total", "Операции ClickHouse", labels),
        "errors": Counter(f"{ns}_errors_total", "Ошибки ClickHouse", labels),
        "latency": Histogram(f"{ns}_latency_seconds", "Латентность операций ClickHouse", labels),
        "bytes_out": Counter(f"{ns}_bytes_out_total", "Отправлено байт вставки", ("db",)),
        "rows_out": Counter(f"{ns}_rows_out_total", "Вставлено строк", ("db",)),
        "rows_in": Counter(f"{ns}_rows_in_total", "Выбрано строк", ("db",)),
    }


# =========================
# Ретраи и бэкофф
# =========================

def _should_retry(exc: Exception) -> bool:
    # ClickHouseError для HTTP 5xx, сетевые OSError, timeout-ы — ретраим
    transient = (TimeoutError, OSError)
    if isinstance(exc, transient):
        return True
    if isinstance(exc, ClickHouseError):
        # у clickhouse-connect есть коды/сообщения; грубо считаем 5xx/транзиентными
        msg = str(exc).lower()
        for key in ("timeout", "temporarily", "transient", "unavailable", "too many", "connection", "reset"):
            if key in msg:
                return True
    return False


def _backoff(attempt: int, base: float, cap: float) -> float:
    t = min(cap, base * (2 ** (attempt - 1)))
    return random.uniform(0, t)


# =========================
# Коннектор
# =========================

@dataclass
class ClickHouseConnector:
    config: ClickHouseConfig
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger("datafabric.connectors.clickhouse"))

    _client: Any = field(init=False, default=None)
    _aclient: Any = field(init=False, default=None)
    _metrics: Dict[str, Any] = field(init=False, default_factory=dict)
    _closed: bool = field(init=False, default=True)

    def __post_init__(self) -> None:
        if not _CH_AVAILABLE:
            raise RuntimeError("clickhouse-connect is not installed")
        self.logger.setLevel(logging.INFO)
        self._metrics = _build_metrics()
        self._client = clickhouse_connect.get_client(
            host=self.config.host,
            port=self.config.port,
            username=self.config.username,
            password=self.config.password,
            database=self.config.database,
            secure=self.config.secure,
            verify=self.config.verify,
            client_name=self.config.client_name,
            connect_timeout=self.config.connect_timeout,
            send_receive_timeout=self.config.send_receive_timeout,
            compress=self.config.compression if self.config.compression != "none" else None,
            settings=self.config.settings or None,
            session_id=self.config.session_id,
        )
        # async клиент опционален; создадим по требованию в aopen()
        self._closed = False

    # ---------- lifecycle ----------

    def close(self) -> None:
        if self._closed:
            return
        try:
            if self._client:
                self._client.close()
        except Exception:
            pass
        self._closed = True

    async def aopen(self) -> None:
        if self._aclient:
            return
        # NOTE: get_async_client доступен в clickhouse-connect>=0.6/0.7
        self._aclient = await clickhouse_connect.get_async_client(  # type: ignore[attr-defined]
            host=self.config.host,
            port=self.config.port,
            username=self.config.username,
            password=self.config.password,
            database=self.config.database,
            secure=self.config.secure,
            verify=self.config.verify,
            client_name=self.config.client_name,
            connect_timeout=self.config.connect_timeout,
            send_receive_timeout=self.config.send_receive_timeout,
            compress=self.config.compression if self.config.compression != "none" else None,
            settings=self.config.settings or None,
            session_id=self.config.session_id,
        )

    async def aclose(self) -> None:
        if self._aclient:
            try:
                await self._aclient.close()  # type: ignore
            except Exception:
                pass
            self._aclient = None

    # ---------- helpers ----------

    def _time_metric(self, op: str, fn, *args, **kwargs):
        start = time.perf_counter()
        try:
            if _TRACER:
                with _TRACER.start_as_current_span(f"clickhouse.{op}"):
                    return fn(*args, **kwargs)
            return fn(*args, **kwargs)
        except Exception as ex:
            if self._metrics:
                try:
                    self._metrics["errors"].labels(self.config.database, op).inc()
                except Exception:
                    pass
            raise
        finally:
            if self._metrics:
                try:
                    self._metrics["ops"].labels(self.config.database, op).inc()
                    self._metrics["latency"].labels(self.config.database, op).observe(time.perf_counter() - start)
                except Exception:
                    pass

    async def _atime_metric(self, op: str, fn, *args, **kwargs):
        start = time.perf_counter()
        try:
            if _TRACER:
                with _TRACER.start_as_current_span(f"clickhouse.{op}"):
                    return await fn(*args, **kwargs)
            return await fn(*args, **kwargs)
        except Exception as ex:
            if self._metrics:
                try:
                    self._metrics["errors"].labels(self.config.database, op).inc()
                except Exception:
                    pass
            raise
        finally:
            if self._metrics:
                try:
                    self._metrics["ops"].labels(self.config.database, op).inc()
                    self._metrics["latency"].labels(self.config.database, op).observe(time.perf_counter() - start)
                except Exception:
                    pass

    def _retrying(self, op: str, fn, *args, **kwargs):
        attempts = 0
        while True:
            try:
                return self._time_metric(op, fn, *args, **kwargs)
            except Exception as ex:
                attempts += 1
                if attempts > self.config.max_retries or not _should_retry(ex):
                    self.logger.error("clickhouse_op_failed", extra={"op": op, "attempts": attempts, "error": str(ex)})
                    raise
                sleep_for = _backoff(attempts, self.config.base_backoff_s, self.config.max_backoff_s)
                self.logger.warning("clickhouse_op_retry", extra={"op": op, "attempt": attempts, "sleep": sleep_for})
                time.sleep(sleep_for)

    async def _aretrying(self, op: str, fn, *args, **kwargs):
        attempts = 0
        while True:
            try:
                return await self._atime_metric(op, fn, *args, **kwargs)
            except Exception as ex:
                attempts += 1
                if attempts > self.config.max_retries or not _should_retry(ex):
                    self.logger.error("clickhouse_op_failed", extra={"op": op, "attempts": attempts, "error": str(ex)})
                    raise
                sleep_for = _backoff(attempts, self.config.base_backoff_s, self.config.max_backoff_s)
                self.logger.warning("clickhouse_op_retry", extra={"op": op, "attempt": attempts, "sleep": sleep_for})
                await _asleep(sleep_for)

    # ---------- публичное sync API ----------

    def ping(self) -> bool:
        def _do():
            # лёгкий SELECT 1
            res = self._client.query("SELECT 1")  # type: ignore
            return bool(res.result_rows if hasattr(res, "result_rows") else res)
        return self._retrying("ping", _do)

    def query(self, sql: str, params: Optional[Dict[str, Any]] = None,
              settings: Optional[Dict[str, Any]] = None, query_id: Optional[str] = None) -> List[Tuple]:
        def _do():
            res = self._client.query(sql, parameters=params or None, settings=settings, query_id=query_id)  # type: ignore
            rows = res.result_rows if hasattr(res, "result_rows") else res
            if self._metrics:
                try:
                    self._metrics["rows_in"].labels(self.config.database).inc(len(rows))
                except Exception:
                    pass
            return rows
        return self._retrying("query", _do)

    def query_df(self, sql: str, params: Optional[Dict[str, Any]] = None,
                 settings: Optional[Dict[str, Any]] = None, query_id: Optional[str] = None):
        try:
            import pandas as pd  # type: ignore
        except Exception as ex:
            raise RuntimeError("pandas is required for query_df") from ex
        def _do():
            # clickhouse-connect умеет напрямую в dataframe()
            return self._client.query_df(sql, parameters=params or None, settings=settings, query_id=query_id)  # type: ignore
        return self._retrying("query_df", _do)

    def execute(self, sql: str, params: Optional[Dict[str, Any]] = None,
                settings: Optional[Dict[str, Any]] = None, query_id: Optional[str] = None) -> None:
        def _do():
            self._client.command(sql, parameters=params or None, settings=settings, query_id=query_id)  # type: ignore
            return None
        return self._retrying("execute", _do)

    def insert_rows(self, table: str, rows: Iterable[Sequence],
                    column_names: Optional[Sequence[str]] = None,
                    settings: Optional[Dict[str, Any]] = None) -> None:
        # Батч‑вставка: поддерживает генераторы
        def _do():
            self._client.insert(table, rows, column_names=column_names, settings=settings)  # type: ignore
            return None
        if self._metrics:
            try:
                # При генераторе не знаем размер — пропускаем, либо завернуть в list перед вызовом
                if isinstance(rows, list):
                    self._metrics["rows_out"].labels(self.config.database).inc(len(rows))
            except Exception:
                pass
        return self._retrying("insert_rows", _do)

    def insert_iter(self, table: str, row_iter: Iterable[Sequence],
                    column_names: Optional[Sequence[str]] = None,
                    settings: Optional[Dict[str, Any]] = None, batch_size: Optional[int] = None) -> None:
        bs = batch_size or self.config.insert_batch_size
        batch: List[Sequence] = []
        for r in row_iter:
            batch.append(r)
            if len(batch) >= bs:
                self.insert_rows(table, batch, column_names, settings)
                batch.clear()
        if batch:
            self.insert_rows(table, batch, column_names, settings)

    # ---------- публичное async API ----------

    async def aping(self) -> bool:
        await self.aopen()
        async def _do():
            res = await self._aclient.query("SELECT 1")  # type: ignore
            return bool(res.result_rows if hasattr(res, "result_rows") else res)
        return await self._aretrying("ping", _do)

    async def aquery(self, sql: str, params: Optional[Dict[str, Any]] = None,
                     settings: Optional[Dict[str, Any]] = None, query_id: Optional[str] = None) -> List[Tuple]:
        await self.aopen()
        async def _do():
            res = await self._aclient.query(sql, parameters=params or None, settings=settings, query_id=query_id)  # type: ignore
            rows = res.result_rows if hasattr(res, "result_rows") else res
            if self._metrics:
                try:
                    self._metrics["rows_in"].labels(self.config.database).inc(len(rows))
                except Exception:
                    pass
            return rows
        return await self._aretrying("query", _do)

    async def aexecute(self, sql: str, params: Optional[Dict[str, Any]] = None,
                       settings: Optional[Dict[str, Any]] = None, query_id: Optional[str] = None) -> None:
        await self.aopen()
        async def _do():
            await self._aclient.command(sql, parameters=params or None, settings=settings, query_id=query_id)  # type: ignore
            return None
        return await self._aretrying("execute", _do)

    async def ainsert_rows(self, table: str, rows: Iterable[Sequence],
                           column_names: Optional[Sequence[str]] = None,
                           settings: Optional[Dict[str, Any]] = None) -> None:
        await self.aopen()
        async def _do():
            await self._aclient.insert(table, rows, column_names=column_names, settings=settings)  # type: ignore
            return None
        if self._metrics and isinstance(rows, list):
            try:
                self._metrics["rows_out"].labels(self.config.database).inc(len(rows))
            except Exception:
                pass
        return await self._aretrying("insert_rows", _do)

    async def ainsert_iter(self, table: str, row_iter: Iterable[Sequence],
                           column_names: Optional[Sequence[str]] = None,
                           settings: Optional[Dict[str, Any]] = None, batch_size: Optional[int] = None) -> None:
        bs = batch_size or self.config.insert_batch_size
        batch: List[Sequence] = []
        for r in row_iter:
            batch.append(r)
            if len(batch) >= bs:
                await self.ainsert_rows(table, list(batch), column_names, settings)
                batch.clear()
        if batch:
            await self.ainsert_rows(table, list(batch), column_names, settings)

    # ---------- миграции/health ----------

    def ensure_migrations_table(self) -> None:
        self.execute("""
        CREATE TABLE IF NOT EXISTS _df_migrations
        (
            id String,
            applied_at DateTime DEFAULT now()
        )
        ENGINE = MergeTree ORDER BY id
        """)

    def apply_migration(self, mig_id: str, sql: str) -> bool:
        self.ensure_migrations_table()
        exists = self.query("SELECT count() FROM _df_migrations WHERE id = %(id)s", {"id": mig_id})[0][0] == 1
        if exists:
            return False
        self.execute(sql)
        self.execute("INSERT INTO _df_migrations (id) VALUES (%(id)s)", {"id": mig_id})
        return True

    def table_exists(self, table: str) -> bool:
        rows = self.query("EXISTS TABLE {table:Identifier}", {"table": table})
        # clickhouse-connect поддерживает Identifier substitution; результат — [(1,)]/[(0,)]
        return bool(rows and rows[0][0] == 1)

    def health(self) -> Dict[str, Any]:
        ok = False
        err = None
        try:
            ok = self.ping()
        except Exception as ex:
            err = str(ex)
        return {"ok": ok, "error": err}

# =========================
# Вспомогательное для asyncio
# =========================

async def _asleep(seconds: float) -> None:
    # Минимальный слип для event loop
    if seconds <= 0:
        return
    await __import__("asyncio").sleep(seconds)


# =========================
# Самопроверка
# =========================

if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    try:
        cfg = ClickHouseConfig.from_env()
        ch = ClickHouseConnector(cfg)
        print("Ping:", ch.ping())
        print("Health:", ch.health())
    except ValidationError as e:
        print("Invalid config:", e)
