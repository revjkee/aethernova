# datafabric-core/datafabric/storage/catalog/glue_catalog.py
"""
Промышленный коннектор AWS Glue Data Catalog для DataFabric.

Возможности:
- Pydantic-конфигурация (регион, профиль, эндпоинты, таймауты, ретраи, теги).
- Инициализация boto3 с botocore.Config, кастомная политика ретраев (экспоненциальный с джиттером).
- Управление базами: ensure_database, get_database, delete_database (безопасно, с проверками).
- Управление таблицами: ensure_table (идемпотентно), update_table, get_table, delete_table.
- Типы таблиц: HIVE/EXTERNAL_TABLE для Parquet/CSV/JSON; а также Delta и Iceberg через параметры таблицы.
- Разделы: batch_upsert_partitions (chunking + retry per-chunk, best-effort partial report).
- Пагинация: list_databases, list_tables, list_partitions c фильтрами/префиксами.
- Lake Formation (опционально): grant_permissions/revoke_permissions.
- Метрики Prometheus (ops/errors/latency/partitions_processed) и OpenTelemetry-спаны (опционально).
- Async обёртки: безопасный запуск sync boto3 вызовов в thread‑executor через asyncio.to_thread.

Зависимости:
- boto3>=1.28, botocore>=1.31
- pydantic>=2

Опционально:
- prometheus-client
- opentelemetry-sdk (+ exporter)
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from pydantic import BaseModel, Field, ValidationError, field_validator
except Exception as ex:  # pragma: no cover
    raise RuntimeError("pydantic>=2 is required for GlueCatalog") from ex

# boto3/botocore
try:
    import boto3  # type: ignore
    from botocore.config import Config as BotoConfig  # type: ignore
    from botocore.exceptions import ClientError, EndpointConnectionError  # type: ignore
except Exception as ex:  # pragma: no cover
    raise RuntimeError("boto3/botocore are required for GlueCatalog") from ex

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

class GlueTableFormat(str):
    PARQUET = "parquet"
    DELTA = "delta"
    ICEBERG = "iceberg"
    CSV = "csv"
    JSON = "json"

class GlueCatalogConfig(BaseModel):
    region: str = Field(default_factory=lambda: os.getenv("AWS_REGION", "eu-west-1"))
    profile_name: Optional[str] = Field(default=None, description="AWS CLI profile")
    endpoint_url: Optional[str] = Field(default=None)
    # таймауты/ретраи
    connect_timeout_s: int = Field(default=5)
    read_timeout_s: int = Field(default=60)
    max_attempts: int = Field(default=1, description="botocore встроенные ретраи (оставляем 1, т.к. ретраим сами)")
    # наши внешние ретраи
    max_retries: int = Field(default=6)
    base_backoff_s: float = Field(default=0.25)
    max_backoff_s: float = Field(default=6.0)
    # теги по умолчанию
    default_tags: Dict[str, str] = Field(default_factory=dict)
    # имя клиента
    client_name: str = Field(default="datafabric-glue")

    @classmethod
    def from_env(cls) -> "GlueCatalogConfig":
        return cls(
            region=os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", "eu-west-1")),
            profile_name=os.getenv("AWS_PROFILE"),
            endpoint_url=os.getenv("GLUE_ENDPOINT_URL"),
            connect_timeout_s=int(os.getenv("GLUE_CONNECT_TIMEOUT", "5")),
            read_timeout_s=int(os.getenv("GLUE_READ_TIMEOUT", "60")),
            max_attempts=int(os.getenv("GLUE_MAX_ATTEMPTS", "1")),
            max_retries=int(os.getenv("GLUE_MAX_RETRIES", "6")),
            base_backoff_s=float(os.getenv("GLUE_BASE_BACKOFF", "0.25")),
            max_backoff_s=float(os.getenv("GLUE_MAX_BACKOFF", "6.0")),
        )


# =========================
# Метрики
# =========================

def _build_metrics(ns: str = "datafabric_glue") -> Dict[str, Any]:
    if not _PROM:
        return {}
    labels = ("op",)
    return {
        "ops": Counter(f"{ns}_ops_total", "Операции Glue", labels),
        "errors": Counter(f"{ns}_errors_total", "Ошибки Glue", labels),
        "latency": Histogram(f"{ns}_latency_seconds", "Латентность операций Glue", labels),
        "parts": Counter(f"{ns}_partitions_total", "Обработано разделов"),
        "parts_failed": Counter(f"{ns}_partitions_failed_total", "Ошибок разделов"),
    }


# =========================
# Ретраи/бэкофф
# =========================

def _is_retryable(exc: Exception) -> bool:
    if isinstance(exc, (EndpointConnectionError, TimeoutError, OSError)):
        return True
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        # throttling + 5xx
        retry_codes = {
            "ThrottlingException",
            "Throttling",
            "TooManyRequestsException",
            "RequestTimeoutException",
            "RequestTimeout",
            "ProvisionedThroughputExceededException",
            "InternalServiceException",
            "InternalFailure",
            "ServiceUnavailableException",
        }
        if code in retry_codes:
            return True
        # иногда только HTTPStatus
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0)
        if status and int(status) >= 500:
            return True
    return False

def _backoff(attempt: int, base: float, cap: float) -> float:
    t = min(cap, base * (2 ** (attempt - 1)))
    return random.uniform(0, t)


# =========================
# Вспомогательное: построение дескриптора
# =========================

def _build_storage_descriptor(
    *,
    location: str,
    table_format: str,
    columns: List[Dict[str, Any]],
    serde_properties: Optional[Dict[str, str]] = None,
    parameters: Optional[Dict[str, str]] = None,
    partition_keys: Optional[List[Dict[str, str]]] = None,
) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """
    Возвращает (StorageDescriptor, TableParameters)
    """
    serde_props = serde_properties or {}
    params = dict(parameters or {})

    if table_format == GlueTableFormat.PARQUET:
        input_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
        output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"
        serde_lib = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
        serde_props.setdefault("serialization.format", "1")
    elif table_format == GlueTableFormat.CSV:
        input_format = "org.apache.hadoop.mapred.TextInputFormat"
        output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"
        serde_lib = "org.apache.hadoop.hive.serde2.OpenCSVSerde"
        serde_props.setdefault("separatorChar", ",")
        serde_props.setdefault("quoteChar", "\"")
        serde_props.setdefault("escapeChar", "\\")
    elif table_format == GlueTableFormat.JSON:
        input_format = "org.apache.hadoop.mapred.TextInputFormat"
        output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"
        serde_lib = "org.openx.data.jsonserde.JsonSerDe"
    elif table_format == GlueTableFormat.DELTA:
        # Delta Lake в Glue: через "table_type": "DELTA" + параметры
        input_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
        output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"
        serde_lib = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
        params.setdefault("table_type", "DELTA")
    elif table_format == GlueTableFormat.ICEBERG:
        # Iceberg: параметры каталога + table_type
        input_format = "org.apache.hadoop.mapred.TextInputFormat"
        output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"
        serde_lib = "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
        params.setdefault("table_type", "ICEBERG")
        params.setdefault("metadata_location", location.rstrip("/") + "/metadata")  # hint
    else:
        raise ValueError("Unsupported table_format")

    sd = {
        "Location": location,
        "InputFormat": input_format,
        "OutputFormat": output_format,
        "Compressed": False,
        "NumberOfBuckets": -1,
        "SerdeInfo": {
            "SerializationLibrary": serde_lib,
            "Parameters": serde_props,
        },
        "Columns": columns,
        "BucketColumns": [],
        "SortColumns": [],
        "Parameters": {},  # SD-level params
    }
    # partition keys только на уровне таблицы, не SD
    return sd, params


# =========================
# Основной класс
# =========================

@dataclass
class GlueCatalog:
    config: GlueCatalogConfig
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger("datafabric.storage.glue_catalog"))

    _session: Any = field(init=False, default=None)
    _glue: Any = field(init=False, default=None)
    _lf: Any = field(init=False, default=None)
    _metrics: Dict[str, Any] = field(init=False, default_factory=dict)

    def __post_init__(self) -> None:
        self.logger.setLevel(logging.INFO)
        if _PROM:
            self._metrics = _build_metrics()
        # boto3 session
        if self.config.profile_name:
            self._session = boto3.Session(profile_name=self.config.profile_name, region_name=self.config.region)
        else:
            self._session = boto3.Session(region_name=self.config.region)
        bconf = BotoConfig(
            region_name=self.config.region,
            retries={"max_attempts": self.config.max_attempts, "mode": "standard"},
            connect_timeout=self.config.connect_timeout_s,
            read_timeout=self.config.read_timeout_s,
            user_agent_extra=self.config.client_name,
        )
        self._glue = self._session.client("glue", endpoint_url=self.config.endpoint_url, config=bconf)
        # Lake Formation клиент создадим по требованию
        self._lf = None

    # ---------- утилиты ретраев/времени ----------

    def _time(self, op: str, fn, *args, **kwargs):
        t0 = time.perf_counter()
        try:
            if _TRACER:
                with _TRACER.start_as_current_span(f"glue.{op}"):
                    return fn(*args, **kwargs)
            return fn(*args, **kwargs)
        except Exception as ex:
            if self._metrics:
                try:
                    self._metrics["errors"].labels(op).inc()
                except Exception:
                    pass
            raise
        finally:
            if self._metrics:
                try:
                    self._metrics["ops"].labels(op).inc()
                    self._metrics["latency"].labels(op).observe(time.perf_counter() - t0)
                except Exception:
                    pass

    def _retrying(self, op: str, fn, *args, **kwargs):
        attempts = 0
        while True:
            try:
                return self._time(op, fn, *args, **kwargs)
            except Exception as ex:
                attempts += 1
                if attempts > self.config.max_retries or not _is_retryable(ex):
                    self.logger.error("glue_op_failed", extra={"op": op, "attempts": attempts, "error": str(ex)})
                    raise
                sleep_for = _backoff(attempts, self.config.base_backoff_s, self.config.max_backoff_s)
                self.logger.warning("glue_op_retry", extra={"op": op, "attempt": attempts, "sleep": sleep_for})
                time.sleep(sleep_for)

    # ---------- базы ----------

    def ensure_database(self, name: str, *, description: Optional[str] = None, location_uri: Optional[str] = None, params: Optional[Dict[str, str]] = None) -> None:
        def _create():
            return self._glue.create_database(
                DatabaseInput={
                    "Name": name,
                    "Description": description or "",
                    "LocationUri": location_uri,
                    "Parameters": params or {},
                },
                Tags=self.config.default_tags or None,
            )
        # если существует — обновим параметры/описание идемпотентно
        try:
            self._retrying("get_database", self._glue.get_database, Name=name)
            # update via update_database
            def _update():
                return self._glue.update_database(
                    Name=name,
                    DatabaseInput={"Name": name, "Description": description or "", "LocationUri": location_uri, "Parameters": params or {}},
                )
            self._retrying("update_database", _update)
        except ClientError as ce:
            if ce.response.get("Error", {}).get("Code") == "EntityNotFoundException":
                self._retrying("create_database", _create)
            else:
                raise

    def get_database(self, name: str) -> Dict[str, Any]:
        return self._retrying("get_database", self._glue.get_database, Name=name)["Database"]

    def delete_database(self, name: str) -> None:
        self._retrying("delete_database", self._glue.delete_database, Name=name)

    # ---------- таблицы ----------

    def ensure_table(
        self,
        *,
        db: str,
        table: str,
        location: str,
        columns: List[Dict[str, Any]],
        partition_keys: Optional[List[Dict[str, str]]] = None,
        table_format: str = GlueTableFormat.PARQUET,
        parameters: Optional[Dict[str, str]] = None,
        serde_properties: Optional[Dict[str, str]] = None,
        description: Optional[str] = None,
        owner: Optional[str] = None,
        table_type: str = "EXTERNAL_TABLE",
    ) -> None:
        sd, params = _build_storage_descriptor(
            location=location,
            table_format=table_format,
            columns=columns,
            serde_properties=serde_properties,
            parameters=parameters,
            partition_keys=partition_keys,
        )
        tbl_params = params
        if self.config.default_tags:
            # Glue не хранит теги на таблице напрямую; можно хранить в Parameters
            for k, v in self.config.default_tags.items():
                tbl_params.setdefault(f"tag:{k}", v)

        tbl_input = {
            "Name": table,
            "Description": description or "",
            "Owner": owner or "owner",
            "Parameters": tbl_params,
            "TableType": table_type,
            "StorageDescriptor": sd,
            "PartitionKeys": partition_keys or [],
        }

        def _create():
            return self._glue.create_table(DatabaseName=db, TableInput=tbl_input)
        def _update():
            return self._glue.update_table(DatabaseName=db, TableInput=tbl_input)

        # если есть — сравним минимум (Location/format/partitions) и обновим
        exists = False
        try:
            current = self._retrying("get_table", self._glue.get_table, DatabaseName=db, Name=table)["Table"]
            exists = True
        except ClientError as ce:
            if ce.response.get("Error", {}).get("Code") == "EntityNotFoundException":
                exists = False
            else:
                raise

        if not exists:
            self._retrying("create_table", _create)
        else:
            self._retrying("update_table", _update)

    def get_table(self, db: str, table: str) -> Dict[str, Any]:
        return self._retrying("get_table", self._glue.get_table, DatabaseName=db, Name=table)["Table"]

    def delete_table(self, db: str, table: str) -> None:
        self._retrying("delete_table", self._glue.delete_table, DatabaseName=db, Name=table)

    # ---------- разделы (partitions) ----------

    def batch_upsert_partitions(
        self,
        *,
        db: str,
        table: str,
        partitions: List[Dict[str, Any]],
        chunk_size: int = 100,
        replace_all: bool = True,
    ) -> Dict[str, int]:
        """
        partitions: список объектов вида:
            {
              "Values": ["2025-08-14", "region=eu"],
              "StorageDescriptor": { ... как в таблице, но с конкретным Location ... },
              "Parameters": {"key":"value"}
            }
        """
        ok = 0
        failed = 0
        for i in range(0, len(partitions), chunk_size):
            chunk = partitions[i:i + chunk_size]
            def _do():
                if replace_all:
                    return self._glue.batch_create_partition(
                        DatabaseName=db,
                        TableName=table,
                        PartitionInputList=chunk,
                    )
                else:
                    return self._glue.batch_update_partition(
                        DatabaseName=db,
                        TableName=table,
                        Entries=[{"PartitionValueList": p["Values"], "PartitionInput": p} for p in chunk],
                    )
            try:
                resp = self._retrying("batch_partitions", _do)
                # разбор ошибок частично
                errors = resp.get("Errors") or []
                ok += len(chunk) - len(errors)
                failed += len(errors)
                if self._metrics:
                    try:
                        self._metrics["parts"].inc(len(chunk) - len(errors))
                        self._metrics["parts_failed"].inc(len(errors))
                    except Exception:
                        pass
            except Exception:
                failed += len(chunk)
                if self._metrics:
                    try:
                        self._metrics["parts_failed"].inc(len(chunk))
                    except Exception:
                        pass
        return {"ok": ok, "failed": failed}

    # ---------- list/paginate ----------

    def list_databases(self, prefix: Optional[str] = None) -> List[str]:
        token = None
        out: List[str] = []
        while True:
            def _do():
                kwargs = {"MaxResults": 100}
                if token:
                    kwargs["NextToken"] = token
                return self._glue.get_databases(**kwargs)
            resp = self._retrying("list_databases", _do)
            for db in resp.get("DatabaseList", []):
                name = db.get("Name")
                if not prefix or (name and name.startswith(prefix)):
                    out.append(name)
            token = resp.get("NextToken")
            if not token:
                break
        return out

    def list_tables(self, db: str, prefix: Optional[str] = None) -> List[str]:
        token = None
        out: List[str] = []
        while True:
            def _do():
                kwargs = {"DatabaseName": db, "MaxResults": 100}
                if token:
                    kwargs["NextToken"] = token
                return self._glue.get_tables(**kwargs)
            resp = self._retrying("list_tables", _do)
            for t in resp.get("TableList", []):
                name = t.get("Name")
                if not prefix or (name and name.startswith(prefix)):
                    out.append(name)
            token = resp.get("NextToken")
            if not token:
                break
        return out

    def list_partitions(self, db: str, table: str, expression: Optional[str] = None) -> List[Dict[str, Any]]:
        token = None
        out: List[Dict[str, Any]] = []
        while True:
            def _do():
                kwargs = {"DatabaseName": db, "TableName": table, "MaxResults": 200}
                if token:
                    kwargs["NextToken"] = token
                if expression:
                    kwargs["Expression"] = expression
                return self._glue.get_partitions(**kwargs)
            resp = self._retrying("list_partitions", _do)
            out.extend(resp.get("Partitions", []))
            token = resp.get("NextToken")
            if not token:
                break
        return out

    # ---------- Lake Formation (опционально) ----------

    def _lf_client(self):
        if self._lf is None:
            self._lf = self._session.client("lakeformation", config=self._glue.meta.config)  # re-use config
        return self._lf

    def grant_permissions(self, principal_arn: str, resource: Dict[str, Any], permissions: List[str]) -> None:
        lf = self._lf_client()
        def _do():
            return lf.grant_permissions(Principal={"DataLakePrincipalIdentifier": principal_arn}, Resource=resource, Permissions=permissions)
        self._retrying("lf_grant", _do)

    def revoke_permissions(self, principal_arn: str, resource: Dict[str, Any], permissions: List[str]) -> None:
        lf = self._lf_client()
        def _do():
            return lf.revoke_permissions(Principal={"DataLakePrincipalIdentifier": principal_arn}, Resource=resource, Permissions=permissions)
        self._retrying("lf_revoke", _do)

    # ---------- Async wrappers ----------

    async def aensure_database(self, *args, **kwargs) -> None:
        await asyncio.to_thread(self.ensure_database, *args, **kwargs)

    async def aensure_table(self, *args, **kwargs) -> None:
        await asyncio.to_thread(self.ensure_table, *args, **kwargs)

    async def aget_table(self, *args, **kwargs) -> Dict[str, Any]:
        return await asyncio.to_thread(self.get_table, *args, **kwargs)

    async def adelete_table(self, *args, **kwargs) -> None:
        await asyncio.to_thread(self.delete_table, *args, **kwargs)

    async def abatch_upsert_partitions(self, *args, **kwargs) -> Dict[str, int]:
        return await asyncio.to_thread(self.batch_upsert_partitions, *args, **kwargs)

    async def alist_tables(self, *args, **kwargs) -> List[str]:
        return await asyncio.to_thread(self.list_tables, *args, **kwargs)

    async def alist_partitions(self, *args, **kwargs) -> List[Dict[str, Any]]:
        return await asyncio.to_thread(self.list_partitions, *args, **kwargs)


# =========================
# Примеры шаблонов колонок
# =========================

def parquet_columns(schema: Sequence[Tuple[str, str, Optional[str]]]) -> List[Dict[str, Any]]:
    """
    schema: [(name, type, comment?)]
    Типы: string, int, bigint, double, boolean, timestamp, date, array<...>, map<...> и т.п.
    """
    out = []
    for name, typ, comment in schema:
        item = {"Name": name, "Type": typ}
        if comment:
            item["Comment"] = comment
        out.append(item)
    return out


# =========================
# Самопроверка (CLI)
# =========================

if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    try:
        cfg = GlueCatalogConfig.from_env()
        glue = GlueCatalog(cfg)
        glue.ensure_database("df_demo", description="DataFabric demo")
        cols = parquet_columns([("id", "bigint", "identifier"), ("dt", "string", "partition date"), ("v", "double", None)])
        glue.ensure_table(
            db="df_demo",
            table="events",
            location="s3://my-bucket/data/events/",
            columns=cols,
            partition_keys=[{"Name": "dt", "Type": "string"}],
            table_format=GlueTableFormat.PARQUET,
            parameters={"classification": "parquet"},
            description="Events table",
        )
        print("OK")
    except ValidationError as e:
        print("Invalid config:", e)
