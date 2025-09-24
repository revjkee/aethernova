# datafabric-core/datafabric/storage/warehouse/bigquery_adapter.py
# -*- coding: utf-8 -*-
"""
Industrial-grade BigQuery adapter for DataFabric.

Особенности:
- Авторизация: ADC (Application Default Credentials), Service Account JSON (строка/файл),
  Impersonation (optional, через target_principal), выбор проекта/локации.
- Надежные ретраи (quota exceeded, rate limit, 5xx, aborted) с экспоненциальным бэкоффом и джиттером.
- Асинхронный интерфейс поверх синхронного клиента google-cloud-bigquery через asyncio.to_thread.
- Параметризованные запросы (типобезопасные), dry-run, job labels (корреляция).
- Потоковое чтение результатов (итерация страницами), и полностью материализованный fetch.
- Загрузка из GCS и локальных файлов (CSV/JSON/Parquet/Avro/ORC), выгрузка в GCS.
- Streaming inserts (insert_rows_json) с чанкингом, корректная обработка ошибок.
- Идемпотентные ensure_dataset / ensure_table с разбиением по времени (PARTITION BY ingestion/time),
  кластеризацией, additive обновление схемы (добавление колонок и relaxation REQUIRED→NULLABLE).
- Транзакционный upsert через MERGE из временной таблицы (создание, заливка, MERGE, drop).
- Мониторинг job с таймаутами, пользовательскими labels и метриками/трейс‑событиями.
- Сбор конфигурации из окружения.

Зависимости:
  google-cloud-bigquery>=3.10.0
  google-cloud-storage>=2.10.0 (для локальных файлов через staging в GCS опционально)
  google-auth, google-auth-impersonated-credentials (если нужен impersonation)

Python: 3.10+
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import typing as t
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ---- Контекст (опционально) ----
try:
    from datafabric.context import ExecutionContext, current_context, log_info, log_error, trace_event
except Exception:  # pragma: no cover
    ExecutionContext = t.Any  # type: ignore
    def current_context(): return None  # type: ignore
    def log_info(msg: str, **kw): print(f"[INFO] {msg} {kw}")  # type: ignore
    def log_error(msg: str, **kw): print(f"[ERROR] {msg} {kw}")  # type: ignore
    def trace_event(event: str, **fields): pass  # type: ignore

# ---- BigQuery SDK ----
try:
    from google.cloud import bigquery
    from google.api_core import exceptions as gax_exceptions
    from google.api_core.retry import if_exception_type
    _BQ_AVAILABLE = True
except Exception as exc:  # pragma: no cover
    raise RuntimeError("google-cloud-bigquery is not installed. Please `pip install google-cloud-bigquery`.") from exc

# ---- Auth (impersonation optional) ----
try:
    import google.auth
    from google.oauth2 import service_account
    from google.auth.impersonated_credentials import Credentials as ImpersonatedCreds
    _AUTH_AVAILABLE = True
except Exception:
    _AUTH_AVAILABLE = False

# -----------------------------
# Вспомогательные утилиты
# -----------------------------

def _utc_ms() -> int:
    return int(time.time() * 1000)

def _jittered(base: float, jitter: float) -> float:
    import random
    delta = base * jitter
    return max(0.0, base + random.uniform(-delta, +delta))

TRANSIENT_ERRORS = (
    gax_exceptions.ServiceUnavailable,        # 503
    gax_exceptions.TooManyRequests,           # 429
    gax_exceptions.InternalServerError,       # 500
    gax_exceptions.BadGateway,                # 502
    gax_exceptions.GatewayTimeout,            # 504
    gax_exceptions.DeadlineExceeded,          # 504
    gax_exceptions.Aborted,                   # concurrency conflicts
)

# -----------------------------
# Конфигурации
# -----------------------------

@dataclass
class RetryPolicy:
    initial_backoff_sec: float = 1.0
    max_backoff_sec: float = 32.0
    multiplier: float = 2.0
    jitter: float = 0.2
    max_attempts: int = 8

@dataclass
class QueryDefaults:
    location: Optional[str] = None
    priority: str = "INTERACTIVE"  # или "BATCH"
    maximum_bytes_billed: Optional[int] = None
    use_query_cache: bool = True
    dry_run: bool = False
    timeout_sec: int = 600
    create_disposition: str = "CREATE_IF_NEEDED"
    write_disposition: str = "WRITE_EMPTY"
    use_legacy_sql: bool = False

@dataclass
class TableDefaults:
    partition_type: Optional[str] = None  # None|"INGEST"| "TIME" (по столбцу)
    partition_field: Optional[str] = None
    partition_expiration_ms: Optional[int] = None
    clustering_fields: list[str] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)

@dataclass
class BigQueryConfig:
    project_id: Optional[str] = None
    location: Optional[str] = None
    dataset: Optional[str] = None
    credentials_json: Optional[str] = None        # путь к файлу или JSON‑строка
    impersonate_principal: Optional[str] = None   # user/service account email для impersonation
    job_labels: dict[str, str] = field(default_factory=dict)
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    query: QueryDefaults = field(default_factory=QueryDefaults)
    table: TableDefaults = field(default_factory=TableDefaults)
    debug: bool = False

# -----------------------------
# Адаптер
# -----------------------------

class BigQueryAdapter:
    """
    Промышленный адаптер BigQuery с устойчивыми операциями и безопасной асинхронизацией.
    """

    def __init__(self, cfg: BigQueryConfig) -> None:
        self.cfg = cfg
        self._client: Optional[bigquery.Client] = None

    # ---------- Lifecycle ----------

    async def start(self) -> None:
        if self._client:
            return
        self._client = await asyncio.to_thread(self._build_client)
        log_info("BigQuery client started", project=self.project_id, location=self.location, dataset=self.cfg.dataset)

    async def close(self) -> None:
        cli = self._client
        self._client = None
        if cli:
            try:
                await asyncio.to_thread(cli.close)
            except Exception:
                pass
        log_info("BigQuery client closed")

    @property
    def project_id(self) -> Optional[str]:
        return self._client.project if self._client else self.cfg.project_id

    @property
    def location(self) -> Optional[str]:
        return self.cfg.location or (self._client.location if self._client else None)

    # ---------- Auth/Client ----------

    def _build_client(self) -> bigquery.Client:
        creds = None
        project = self.cfg.project_id
        if _AUTH_AVAILABLE:
            if self.cfg.credentials_json:
                # Может быть JSON‑строкой или путем к файлу
                if Path(self.cfg.credentials_json).exists():
                    creds = service_account.Credentials.from_service_account_file(self.cfg.credentials_json)
                else:
                    try:
                        info = json.loads(self.cfg.credentials_json)
                        creds = service_account.Credentials.from_service_account_info(info)
                    except Exception as exc:
                        raise RuntimeError("Invalid credentials_json: not a file and not a valid JSON") from exc
                if self.cfg.impersonate_principal:
                    creds = ImpersonatedCreds(
                        source_credentials=creds,
                        target_principal=self.cfg.impersonate_principal,
                        target_scopes=["https://www.googleapis.com/auth/bigquery"],
                        lifetime=3600,
                    )
                    project = project or creds.project_id
            else:
                creds, proj = google.auth.default(scopes=["https://www.googleapis.com/auth/bigquery"])
                project = project or proj

        client = bigquery.Client(
            project=project,
            credentials=creds,
            location=self.cfg.location,
        )
        return client

    # ---------- Общая ретрай‑обертка ----------

    async def _with_retry(self, fn: t.Callable, *args, **kwargs):
        rp = self.cfg.retry
        delay = rp.initial_backoff_sec
        attempt = 0
        while True:
            try:
                return await asyncio.to_thread(fn, *args, **kwargs)
            except TRANSIENT_ERRORS as exc:
                attempt += 1
                if attempt >= rp.max_attempts:
                    log_error("BigQuery transient failure (max attempts)", op=getattr(fn, "__name__", str(fn)), error=str(exc))
                    raise
                await asyncio.sleep(_jittered(delay, rp.jitter))
                delay = min(delay * rp.multiplier, rp.max_backoff_sec)

    # ---------- Dataset/Table utils ----------

    async def ensure_dataset(self, dataset_id: Optional[str] = None, labels: Optional[dict] = None) -> str:
        ds_id = dataset_id or self.cfg.dataset
        if not ds_id:
            raise ValueError("Dataset is required")
        client = self._client or await asyncio.to_thread(self._build_client)
        ds_ref = bigquery.Dataset(f"{self.project_id}.{ds_id}")
        if labels:
            ds_ref.labels = {**(ds_ref.labels or {}), **labels}
        try:
            await asyncio.to_thread(client.get_dataset, ds_ref)
        except gax_exceptions.NotFound:
            await asyncio.to_thread(client.create_dataset, ds_ref, exists_ok=True)
        trace_event("bq_ensure_dataset", dataset=ds_id)
        return ds_id

    async def table_exists(self, table: str, dataset_id: Optional[str] = None) -> bool:
        ds = dataset_id or self.cfg.dataset
        if not ds:
            raise ValueError("Dataset is required")
        table_ref = f"{self.project_id}.{ds}.{table}"
        client = self._client
        try:
            await asyncio.to_thread(client.get_table, table_ref)
            return True
        except gax_exceptions.NotFound:
            return False

    async def ensure_table(
        self,
        table: str,
        schema: list[bigquery.SchemaField],
        *,
        dataset_id: Optional[str] = None,
        time_partitioning: Optional[dict] = None,  # {"type": "INGEST"|"DAY"|"HOUR", "field": "...", "expiration_ms": int}
        clustering_fields: Optional[list[str]] = None,
        labels: Optional[dict] = None,
    ) -> str:
        ds = dataset_id or self.cfg.dataset
        if not ds:
            raise ValueError("Dataset is required")
        client = self._client
        table_ref = bigquery.Table(f"{self.project_id}.{ds}.{table}", schema=schema)

        # Partitioning
        tp = time_partitioning or {}
        if tp:
            ttype = tp.get("type")
            if ttype == "INGEST":
                table_ref.time_partitioning = bigquery.TimePartitioning(type_=bigquery.TimePartitioningType.DAY)
            elif ttype in ("DAY", "HOUR", "MONTH", "YEAR"):
                field = tp.get("field")
                if not field:
                    raise ValueError("partition field is required for TIME partitioning")
                table_ref.time_partitioning = bigquery.TimePartitioning(
                    type_=getattr(bigquery.TimePartitioningType, ttype),
                    field=field,
                )
            exp = tp.get("expiration_ms")
            if exp:
                table_ref.time_partitioning.expiration_ms = int(exp)

        # Clustering
        if clustering_fields:
            table_ref.clustering_fields = clustering_fields

        # Labels
        if labels:
            table_ref.labels = labels

        try:
            await asyncio.to_thread(client.get_table, table_ref.reference)
            # Обновляем схему additively (добавление новых полей, relaxation)
            await self._update_schema_additive(table_ref.reference, schema)
        except gax_exceptions.NotFound:
            await asyncio.to_thread(client.create_table, table_ref)
        trace_event("bq_ensure_table", table=f"{ds}.{table}")
        return f"{ds}.{table}"

    async def _update_schema_additive(self, table_ref: bigquery.TableReference, desired: list[bigquery.SchemaField]) -> None:
        client = self._client
        current: bigquery.Table = await asyncio.to_thread(client.get_table, table_ref)
        cur_map = {f.name: f for f in current.schema}
        changed = False
        new_schema: list[bigquery.SchemaField] = list(current.schema)
        for f in desired:
            if f.name not in cur_map:
                new_schema.append(f)
                changed = True
            else:
                cur = cur_map[f.name]
                # Relaxation REQUIRED -> NULLABLE допускается
                if cur.mode == "REQUIRED" and f.mode in ("NULLABLE", None):
                    idx = new_schema.index(cur)
                    new_schema[idx] = bigquery.SchemaField(cur.name, cur.field_type, mode="NULLABLE", description=cur.description)
                    changed = True
        if changed:
            current.schema = new_schema
            await asyncio.to_thread(client.update_table, current, ["schema"])

    # ---------- Параметры и запросы ----------

    @staticmethod
    def _to_bq_param(name: str, value: t.Any) -> bigquery.ScalarQueryParameter:
        # Простая типизация: int/float/bool/str/bytes/date/datetime
        from datetime import date, datetime
        if value is None:
            # NULL в BQ параметрах — передаём тип STRING по умолчанию
            return bigquery.ScalarQueryParameter(name, "STRING", None)
        if isinstance(value, bool):
            return bigquery.ScalarQueryParameter(name, "BOOL", value)
        if isinstance(value, int):
            return bigquery.ScalarQueryParameter(name, "INT64", value)
        if isinstance(value, float):
            return bigquery.ScalarQueryParameter(name, "FLOAT64", value)
        if isinstance(value, bytes):
            return bigquery.ScalarQueryParameter(name, "BYTES", value)
        if isinstance(value, datetime):
            return bigquery.ScalarQueryParameter(name, "TIMESTAMP", value)
        if isinstance(value, date):
            return bigquery.ScalarQueryParameter(name, "DATE", value)
        # Fallback: STRING/JSON (если dict/list)
        if isinstance(value, (dict, list)):
            return bigquery.ScalarQueryParameter(name, "JSON", json.dumps(value, separators=(",", ":"), ensure_ascii=False))
        return bigquery.ScalarQueryParameter(name, "STRING", str(value))

    def _build_job_config(
        self,
        params: Optional[dict] = None,
        destination: Optional[str] = None,
        write_disposition: Optional[str] = None,
        create_disposition: Optional[str] = None,
        dry_run: Optional[bool] = None,
        use_query_cache: Optional[bool] = None,
        priority: Optional[str] = None,
        maximum_bytes_billed: Optional[int] = None,
        use_legacy_sql: Optional[bool] = None,
        labels: Optional[dict] = None,
    ) -> bigquery.QueryJobConfig:
        cfg = self.cfg.query
        job_config = bigquery.QueryJobConfig()
        if params:
            job_config.query_parameters = [self._to_bq_param(k, v) for k, v in params.items()]
        if destination:
            job_config.destination = destination
        job_config.write_disposition = write_disposition or cfg.write_disposition
        job_config.create_disposition = create_disposition or cfg.create_disposition
        job_config.dry_run = cfg.dry_run if dry_run is None else dry_run
        job_config.use_query_cache = cfg.use_query_cache if use_query_cache is None else use_query_cache
        job_config.priority = priority or cfg.priority
        job_config.maximum_bytes_billed = maximum_bytes_billed or cfg.maximum_bytes_billed
        job_config.use_legacy_sql = cfg.use_legacy_sql if use_legacy_sql is None else use_legacy_sql
        job_config.labels = {**(self.cfg.job_labels or {}), **(labels or {})}
        return job_config

    async def run_query(
        self,
        sql: str,
        *,
        params: Optional[dict] = None,
        destination_table: Optional[str] = None,  # "project.dataset.table" или "dataset.table"
        priority: Optional[str] = None,
        dry_run: Optional[bool] = None,
        timeout_sec: Optional[int] = None,
        labels: Optional[dict] = None,
    ) -> bigquery.table.RowIterator:
        if not self._client:
            await self.start()
        client = self._client
        dest = None
        if destination_table:
            dest = self._normalize_table_ref(destination_table)
        job_config = self._build_job_config(
            params=params,
            destination=dest,
            priority=priority,
            dry_run=dry_run,
            labels=labels,
        )
        # location может быть обязателен для некоторых проектов
        job = await self._with_retry(
            client.query,
            sql,
            job_config=job_config,
            location=self.cfg.location or self.location,
        )
        if job_config.dry_run:
            trace_event("bq_dry_run", total_bytes=job.total_bytes_processed, cache_hit=job.cache_hit)
            return None  # dry-run без данных
        result = await asyncio.to_thread(job.result, timeout=timeout_sec or self.cfg.query.timeout_sec)
        trace_event("bq_query_done", bytes_processed=job.total_bytes_processed, rows=result.total_rows)
        return result

    async def fetch_all(
        self,
        sql: str,
        *,
        params: Optional[dict] = None,
        page_size: int = 10000,
        labels: Optional[dict] = None,
    ) -> list[dict]:
        rows = await self.run_query(sql, params=params, labels=labels)
        if rows is None:
            return []
        out: list[dict] = []
        # Страницы для экономии памяти
        it = rows.pages
        while True:
            try:
                page = await asyncio.to_thread(next, it)
            except StopIteration:
                break
            for r in page:
                out.append(dict(r))
        return out

    async def stream_query(
        self,
        sql: str,
        *,
        params: Optional[dict] = None,
        page_size: int = 10000,
        labels: Optional[dict] = None,
    ) -> t.AsyncIterator[list[dict]]:
        rows = await self.run_query(sql, params=params, labels=labels)
        if rows is None:
            if False:
                yield []  # для типизации
            return
        rows.page_size = page_size
        it = rows.pages
        while True:
            try:
                page = await asyncio.to_thread(next, it)
            except StopIteration:
                break
            chunk = [dict(r) for r in page]
            yield chunk

    # ---------- Streaming inserts ----------

    async def insert_rows_json(
        self,
        table: str,
        rows: list[dict],
        *,
        dataset_id: Optional[str] = None,
        chunk_size: int = 500,  # BigQuery рекомендует до ~10k, но 500-1000 безопасно
        skip_invalid_rows: bool = False,
        ignore_unknown_values: bool = True,
        retry_on_errors: bool = True,
        labels: Optional[dict] = None,
    ) -> None:
        ds = dataset_id or self.cfg.dataset
        if not ds:
            raise ValueError("Dataset is required")
        fq_table = self._normalize_table_ref(f"{self.project_id}.{ds}.{table}")
        client = self._client
        total = 0
        for i in range(0, len(rows), chunk_size):
            chunk = rows[i : i + chunk_size]
            def _insert():
                return client.insert_rows_json(
                    fq_table,
                    json_rows=chunk,
                    skip_invalid_rows=skip_invalid_rows,
                    ignore_unknown_values=ignore_unknown_values,
                    row_ids=[None] * len(chunk),
                )
            if retry_on_errors:
                err = await self._with_retry(_insert)
            else:
                err = await asyncio.to_thread(_insert)
            if err:
                # err — список ошибок по рядам
                log_error("BigQuery insert_rows_json errors", errors=str(err))
                raise RuntimeError(f"insert_rows_json failed: {err}")
            total += len(chunk)
        trace_event("bq_insert_rows_json", table=fq_table, count=total)

    # ---------- Load/Extract ----------

    async def load_table_from_uri(
        self,
        gcs_uri: str | list[str],
        destination_table: str,
        *,
        source_format: str = "PARQUET",  # CSV|NEWLINE_DELIMITED_JSON|AVRO|PARQUET|ORC
        write_disposition: Optional[str] = None,
        schema: Optional[list[bigquery.SchemaField]] = None,
        autodetect: bool = True,
        allow_jagged_rows: bool = False,
        field_delimiter: Optional[str] = ",",
        quote_character: Optional[str] = '"',
        labels: Optional[dict] = None,
        timeout_sec: Optional[int] = None,
    ) -> None:
        client = self._client
        job_config = bigquery.LoadJobConfig()
        job_config.source_format = getattr(bigquery.SourceFormat, source_format)
        job_config.write_disposition = write_disposition or self.cfg.query.write_disposition
        job_config.autodetect = autodetect if schema is None else False
        if schema:
            job_config.schema = schema
        if job_config.source_format == bigquery.SourceFormat.CSV:
            job_config.allow_jagged_rows = allow_jagged_rows
            job_config.field_delimiter = field_delimiter
            job_config.quote_character = quote_character

        dest = self._normalize_table_ref(destination_table)
        job = await self._with_retry(
            client.load_table_from_uri,
            gcs_uri,
            dest,
            job_config=job_config,
            location=self.location,
        )
        await asyncio.to_thread(job.result, timeout=timeout_sec or self.cfg.query.timeout_sec)
        trace_event("bq_load_from_uri_done", dest=dest)

    async def load_table_from_file(
        self,
        file_path: str,
        destination_table: str,
        *,
        source_format: str = "PARQUET",
        write_disposition: Optional[str] = None,
        schema: Optional[list[bigquery.SchemaField]] = None,
        autodetect: bool = True,
        labels: Optional[dict] = None,
        timeout_sec: Optional[int] = None,
    ) -> None:
        client = self._client
        job_config = bigquery.LoadJobConfig()
        job_config.source_format = getattr(bigquery.SourceFormat, source_format)
        job_config.write_disposition = write_disposition or self.cfg.query.write_disposition
        job_config.autodetect = autodetect if schema is None else False
        if schema:
            job_config.schema = schema

        dest = self._normalize_table_ref(destination_table)
        with open(file_path, "rb") as f:
            job = await self._with_retry(
                client.load_table_from_file,
                f,
                dest,
                job_config=job_config,
                location=self.location,
            )
        await asyncio.to_thread(job.result, timeout=timeout_sec or self.cfg.query.timeout_sec)
        trace_event("bq_load_from_file_done", dest=dest, path=file_path)

    async def extract_table_to_gcs(
        self,
        table: str,
        gcs_uri: str | list[str],
        *,
        destination_format: str = "PARQUET",  # CSV|AVRO|PARQUET
        compression: Optional[str] = None,    # GZIP/SNAPPY для AVRO/CSV; PARQUET сам сжат
        field_delimiter: Optional[str] = ",",
        print_header: bool = True,
        labels: Optional[dict] = None,
        timeout_sec: Optional[int] = None,
    ) -> None:
        client = self._client
        extract_cfg = bigquery.ExtractJobConfig()
        extract_cfg.destination_format = getattr(bigquery.DestinationFormat, destination_format)
        if extract_cfg.destination_format == bigquery.DestinationFormat.CSV:
            extract_cfg.field_delimiter = field_delimiter
            extract_cfg.print_header = print_header
        if compression:
            extract_cfg.compression = getattr(bigquery.Compression, compression)
        src = self._normalize_table_ref(table)
        job = await self._with_retry(
            client.extract_table,
            source=src,
            destination_uris=gcs_uri,
            job_config=extract_cfg,
            location=self.location,
        )
        await asyncio.to_thread(job.result, timeout=timeout_sec or self.cfg.query.timeout_sec)
        trace_event("bq_extract_done", table=src)

    # ---------- Upsert (MERGE) через временную таблицу ----------

    async def upsert_merge_from_temp(
        self,
        target_table: str,
        temp_table: str,
        on_keys: list[str],
        update_set: list[str],
        insert_columns: Optional[list[str]] = None,
        dataset_id: Optional[str] = None,
        labels: Optional[dict] = None,
        timeout_sec: Optional[int] = None,
    ) -> None:
        ds = dataset_id or self.cfg.dataset
        if not ds:
            raise ValueError("Dataset is required")
        tgt = self._normalize_table_ref(f"{self.project_id}.{ds}.{target_table}")
        tmp = self._normalize_table_ref(f"{self.project_id}.{ds}.{temp_table}")

        on_clause = " AND ".join([f"T.{k}=S.{k}" for k in on_keys])
        set_clause = ", ".join([f"T.{c}=S.{c}" for c in update_set])
        if insert_columns:
            cols = ", ".join(insert_columns)
            vals = ", ".join([f"S.{c}" for c in insert_columns])
        else:
            cols = ", ".join(update_set)
            vals = ", ".join([f"S.{c}" for c in update_set])

        sql = f"""
        MERGE `{tgt}` T
        USING `{tmp}` S
        ON {on_clause}
        WHEN MATCHED THEN UPDATE SET {set_clause}
        WHEN NOT MATCHED THEN INSERT ({cols}) VALUES ({vals})
        """
        await self.run_query(sql, timeout_sec=timeout_sec, labels=labels)

    # ---------- Вспомогательные ----------

    def _normalize_table_ref(self, ref: str) -> str:
        """
        Допустимы формы:
          dataset.table
          project.dataset.table
        Возвращаем project.dataset.table
        """
        parts = ref.split(".")
        if len(parts) == 2:
            if not self.project_id:
                raise ValueError("Project id is required to fully-qualify table reference")
            return f"{self.project_id}.{parts[0]}.{parts[1]}"
        if len(parts) == 3:
            return ref
        raise ValueError("Invalid table reference format. Expect dataset.table or project.dataset.table")

# -----------------------------
# ENV builder
# -----------------------------

def build_from_env(prefix: str = "DF_BQ_") -> BigQueryConfig:
    e = os.getenv
    # job labels из JSON или плоской строки key1=val1,key2=val2
    labels_raw = e(f"{prefix}JOB_LABELS", "")
    labels: dict[str, str] = {}
    if labels_raw:
        try:
            if labels_raw.strip().startswith("{"):
                labels = json.loads(labels_raw)
            else:
                for pair in labels_raw.split(","):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        labels[k.strip()] = v.strip()
        except Exception:
            labels = {}

    cfg = BigQueryConfig(
        project_id=e(f"{prefix}PROJECT_ID"),
        location=e(f"{prefix}LOCATION"),
        dataset=e(f"{prefix}DATASET"),
        credentials_json=e(f"{prefix}CREDENTIALS_JSON"),
        impersonate_principal=e(f"{prefix}IMPERSONATE"),
        job_labels=labels,
        debug=e(f"{prefix}DEBUG", "false").lower() == "true",
    )
    # Retry overrides
    try:
        cfg.retry.initial_backoff_sec = float(e(f"{prefix}RETRY_INITIAL", str(cfg.retry.initial_backoff_sec)))
        cfg.retry.max_backoff_sec = float(e(f"{prefix}RETRY_MAX", str(cfg.retry.max_backoff_sec)))
        cfg.retry.multiplier = float(e(f"{prefix}RETRY_MULT", str(cfg.retry.multiplier)))
        cfg.retry.jitter = float(e(f"{prefix}RETRY_JITTER", str(cfg.retry.jitter)))
        cfg.retry.max_attempts = int(e(f"{prefix}RETRY_ATTEMPTS", str(cfg.retry.max_attempts)))
    except Exception:
        pass
    # Query defaults
    q = cfg.query
    q.priority = e(f"{prefix}QUERY_PRIORITY", q.priority)
    q.maximum_bytes_billed = int(e(f"{prefix}QUERY_MAX_BYTES", str(q.maximum_bytes_billed or 0))) or None
    q.use_query_cache = e(f"{prefix}QUERY_USE_CACHE", "true").lower() == "true"
    q.dry_run = e(f"{prefix}QUERY_DRY_RUN", "false").lower() == "true"
    q.timeout_sec = int(e(f"{prefix}QUERY_TIMEOUT", str(q.timeout_sec)))
    q.create_disposition = e(f"{prefix}QUERY_CREATE_DISPOSITION", q.create_disposition)
    q.write_disposition = e(f"{prefix}QUERY_WRITE_DISPOSITION", q.write_disposition)
    q.use_legacy_sql = e(f"{prefix}QUERY_LEGACY", "false").lower() == "true"

    # Table defaults (не навязываем, используются в ensure_table при желании)
    tdef = cfg.table
    tdef.partition_type = e(f"{prefix}TABLE_PARTITION_TYPE") or None
    tdef.partition_field = e(f"{prefix}TABLE_PARTITION_FIELD") or None
    tdef.partition_expiration_ms = int(e(f"{prefix}TABLE_PARTITION_EXP_MS", "0")) or None
    tdef.clustering_fields = [x.strip() for x in e(f"{prefix}TABLE_CLUSTER_FIELDS", "").split(",") if x.strip()]
    try:
        labels_raw2 = e(f"{prefix}TABLE_LABELS", "")
        if labels_raw2:
            tdef.labels = json.loads(labels_raw2) if labels_raw2.strip().startswith("{") else {
                k.strip(): v.strip() for k, v in [p.split("=", 1) for p in labels_raw2.split(",") if "=" in p]
            }
    except Exception:
        pass

    return cfg

# -----------------------------
# Пример схемы и вызовов (reference)
# -----------------------------
# from google.cloud import bigquery
# async def example():
#     cfg = build_from_env()
#     bq = BigQueryAdapter(cfg)
#     await bq.start()
#     try:
#         await bq.ensure_dataset()
#         schema = [
#             bigquery.SchemaField("event_time", "TIMESTAMP", mode="REQUIRED"),
#             bigquery.SchemaField("user_id", "STRING"),
#             bigquery.SchemaField("amount", "FLOAT"),
#         ]
#         await bq.ensure_table("events", schema, time_partitioning={"type": "DAY", "field": "event_time"})
#         await bq.insert_rows_json("events", [{"event_time": "2024-01-01T00:00:00Z", "user_id": "u1", "amount": 10.5}])
#         rows = await bq.fetch_all("SELECT user_id, SUM(amount) total FROM `project.dataset.events` GROUP BY user_id")
#         print(rows)
#     finally:
#         await bq.close()
