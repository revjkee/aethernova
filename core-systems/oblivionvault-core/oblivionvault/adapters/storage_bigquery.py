# File: oblivionvault/adapters/storage_bigquery.py
# Industrial BigQuery storage adapter for oblivionvault-core
# Python 3.10+

from __future__ import annotations

import concurrent.futures
import contextlib
import dataclasses
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

try:
    # Optional OpenTelemetry tracing
    from opentelemetry import trace  # type: ignore
    _TRACER = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    trace = None  # type: ignore
    _TRACER = None  # type: ignore

try:
    import pandas as pd  # Optional, used in load_dataframe
except Exception:  # pragma: no cover
    pd = None  # type: ignore

from google.api_core import exceptions as gexc
from google.api_core import retry as garetry
from google.cloud import bigquery


# ----------------------------- Exceptions ---------------------------------- #

class BigQueryAdapterError(RuntimeError):
    """Base adapter error for oblivionvault BigQuery operations."""


class BigQuerySecurityError(BigQueryAdapterError):
    """Raised on security-related misconfiguration (e.g., CMEK required but missing)."""


class BigQuerySchemaError(BigQueryAdapterError):
    """Raised when table schema validation fails."""


# ----------------------------- Utilities ----------------------------------- #

def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _gen_insert_id() -> str:
    # 128-bit randomness; suitable for idempotent streaming inserts
    return uuid.uuid4().hex


@contextlib.contextmanager
def _maybe_span(name: str):
    """Create an OpenTelemetry span if OTel is available; no-op otherwise."""
    if _TRACER:
        with _TRACER.start_as_current_span(name) as span:
            yield span
    else:
        yield None


def _serialize_for_json(v: Any) -> Any:
    if isinstance(v, datetime):
        # BigQuery expects RFC3339/ISO 8601 strings for DATETIME/TIMESTAMP in JSON
        return v.astimezone(timezone.utc).isoformat()
    return v


# ------------------------------- Config ------------------------------------ #

@dataclass(slots=True)
class BigQueryConfig:
    project_id: str = field(default_factory=lambda: os.getenv("BQ_PROJECT_ID", ""))
    dataset: str = field(default_factory=lambda: os.getenv("BQ_DATASET", "oblivionvault"))
    location: str = field(default_factory=lambda: os.getenv("BQ_LOCATION", "EU"))
    labels: Dict[str, str] = field(default_factory=lambda: {
        "system": "oblivionvault-core",
        "component": "storage",
        "owner": "security-platform",
    })

    # Security / Compliance
    use_cmek: bool = field(default_factory=lambda: os.getenv("BQ_USE_CMEK", "false").lower() == "true")
    kms_key_name: Optional[str] = field(default_factory=lambda: os.getenv("BQ_KMS_KEY_NAME", "") or None)
    require_partition_filter: bool = True

    # Job behavior
    default_timeout: int = 120  # seconds
    max_retry_attempts: int = 5
    initial_retry_delay: float = 1.0
    max_retry_delay: float = 8.0
    jitter: float = 0.1  # additional randomization could be added if needed

    # Data retention and partition defaults
    default_table_expiration_ms: Optional[int] = None  # None means never expire
    default_partition_expiration_ms: Optional[int] = None

    # Execution
    max_workers: int = max(os.cpu_count() or 4, 4)

    # Audit
    audit_table: Optional[str] = None  # e.g., "dataset.audit_log"

    def validate(self) -> None:
        if self.use_cmek and not self.kms_key_name:
            raise BigQuerySecurityError("CMEK is required but BQ_KMS_KEY_NAME is not set.")
        if not self.project_id:
            raise BigQueryAdapterError("BQ_PROJECT_ID is required.")
        if not self.dataset:
            raise BigQueryAdapterError("BQ_DATASET is required.")


# --------------------------- Schema helpers -------------------------------- #

BQField = bigquery.SchemaField


def schema_from_pydantic(model_cls: Any) -> List[BQField]:
    """
    Convert a Pydantic BaseModel to BigQuery schema.
    This function is optional: it imports pydantic at runtime if available.
    """
    try:
        from pydantic import BaseModel  # type: ignore
    except Exception as e:  # pragma: no cover
        raise BigQuerySchemaError("Pydantic is not installed but schema_from_pydantic was requested.") from e

    if not issubclass(model_cls, BaseModel):  # type: ignore
        raise BigQuerySchemaError("model_cls must be a subclass of pydantic.BaseModel")

    fields: List[BQField] = []
    for name, ann in model_cls.model_fields.items():  # pydantic v2
        # Basic mapping; extend as needed
        bq_type = "STRING"
        if ann.annotation in (int, Optional[int]):
            bq_type = "INT64"
        elif ann.annotation in (float, Optional[float]):
            bq_type = "FLOAT64"
        elif ann.annotation in (bool, Optional[bool]):
            bq_type = "BOOL"
        elif ann.annotation in (datetime, Optional[datetime]):
            bq_type = "TIMESTAMP"
        # else: default STRING
        mode = "NULLABLE"
        fields.append(BQField(name=name, field_type=bq_type, mode=mode))
    return fields


def validate_schema(schema: Sequence[BQField]) -> None:
    seen = set()
    for f in schema:
        if f.name in seen:
            raise BigQuerySchemaError(f"Duplicate field in schema: {f.name}")
        seen.add(f.name)


# ----------------------------- Adapter ------------------------------------- #

class BigQueryStorageAdapter:
    """
    Industrial BigQuery adapter for oblivionvault-core with:
    - Dataset/table ensure & configuration (labels, location, CMEK, expiration)
    - Partitioning & clustering
    - Safe parameterized queries
    - Idempotent streaming inserts (insertId)
    - DataFrame loading (optional)
    - Upsert via MERGE
    - Retry/timeout policy
    - Audit logging
    - Async wrappers via ThreadPoolExecutor
    """

    def __init__(self, config: Optional[BigQueryConfig] = None, logger: Optional[logging.Logger] = None):
        self.config = config or BigQueryConfig()
        self.config.validate()

        self._logger = logger or logging.getLogger(__name__)
        self._logger.debug("Initializing BigQueryStorageAdapter", extra={"config": dataclasses.asdict(self.config)})

        self._client = bigquery.Client(project=self.config.project_id, location=self.config.location)
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_workers, thread_name_prefix="bq-adapter")
        self._lock = threading.RLock()

    # --------------------------- Lifecycle --------------------------------- #

    def close(self) -> None:
        self._logger.debug("Shutting down BigQueryStorageAdapter")
        try:
            self._executor.shutdown(wait=True, cancel_futures=False)
        finally:
            self._client.close()

    def __enter__(self) -> "BigQueryStorageAdapter":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # --------------------------- Retry policy ------------------------------- #

    def _retry(self) -> garetry.Retry:
        return garetry.Retry(
            predicate=garetry.if_exception_type(
                gexc.InternalServerError,
                gexc.BadGateway,
                gexc.ServiceUnavailable,
                gexc.GatewayTimeout,
                gexc.TooManyRequests,
                gexc.DeadlineExceeded,
            ),
            initial=self.config.initial_retry_delay,
            maximum=self.config.max_retry_delay,
            multiplier=2.0,
            deadline=self.config.default_timeout,
        )

    # --------------------------- Dataset ops -------------------------------- #

    def ensure_dataset(self) -> bigquery.Dataset:
        with _maybe_span("bq.ensure_dataset"):
            dataset_ref = bigquery.Dataset(f"{self.config.project_id}.{self.config.dataset}")
            dataset_ref.location = self.config.location
            dataset_ref.labels = {**self.config.labels, "dataset": self.config.dataset}

            if self.config.default_table_expiration_ms is not None:
                dataset_ref.default_table_expiration_ms = self.config.default_table_expiration_ms
            if self.config.default_partition_expiration_ms is not None:
                dataset_ref.default_partition_expiration_ms = self.config.default_partition_expiration_ms

            if self.config.use_cmek and self.config.kms_key_name:
                dataset_ref.default_encryption_configuration = bigquery.EncryptionConfiguration(
                    kms_key_name=self.config.kms_key_name
                )

            try:
                ds = self._client.get_dataset(dataset_ref.reference)
                self._logger.info("Dataset exists", extra={"dataset": ds.full_dataset_id})
                return ds
            except gexc.NotFound:
                self._logger.info("Creating dataset", extra={"dataset": dataset_ref.dataset_id})
                ds = self._client.create_dataset(dataset_ref, timeout=self.config.default_timeout)
                return ds

    # --------------------------- Table ops ---------------------------------- #

    def table_exists(self, table: str) -> bool:
        table_ref = f"{self.config.project_id}.{self.config.dataset}.{table}"
        try:
            self._client.get_table(table_ref)
            return True
        except gexc.NotFound:
            return False

    def ensure_table(
        self,
        table: str,
        schema: Sequence[BQField],
        description: Optional[str] = None,
        time_partitioning_field: Optional[str] = None,
        time_partitioning_type: str = "DAY",
        partition_expiration_ms: Optional[int] = None,
        clustering_fields: Optional[Sequence[str]] = None,
        labels: Optional[Dict[str, str]] = None,
    ) -> bigquery.Table:
        validate_schema(schema)
        with _maybe_span("bq.ensure_table"):
            table_id = f"{self.config.project_id}.{self.config.dataset}.{table}"
            labels_all = {**self.config.labels, **(labels or {}), "table": table}

            try:
                tbl = self._client.get_table(table_id)
                # simple schema drift check (names only); extend if needed
                existing_names = [f.name for f in tbl.schema]
                requested_names = [f.name for f in schema]
                if existing_names != requested_names:
                    self._logger.warning(
                        "Schema mismatch detected (names differ). Consider migration.",
                        extra={"table": table_id, "existing": existing_names, "requested": requested_names},
                    )
                return tbl
            except gexc.NotFound:
                pass

            tbl = bigquery.Table(table_id, schema=list(schema))
            tbl.labels = labels_all
            if description:
                tbl.description = description

            if time_partitioning_field:
                tbl.time_partitioning = bigquery.TimePartitioning(
                    type_=time_partitioning_type,
                    field=time_partitioning_field,
                    expiration_ms=partition_expiration_ms or self.config.default_partition_expiration_ms,
                    require_partition_filter=self.config.require_partition_filter,
                )
            if clustering_fields:
                tbl.clustering_fields = list(clustering_fields)

            if self.config.use_cmek and self.config.kms_key_name:
                tbl.encryption_configuration = bigquery.EncryptionConfiguration(kms_key_name=self.config.kms_key_name)

            created = self._client.create_table(tbl, timeout=self.config.default_timeout)
            self._logger.info("Created table", extra={"table": table_id})
            return created

    # ----------------------- Insert / Load ops ------------------------------ #

    def insert_rows_json(
        self,
        table: str,
        rows: Sequence[Dict[str, Any]],
        skip_invalid_rows: bool = False,
        ignore_unknown_values: bool = False,
        add_insert_ids: bool = True,
        trace_id: Optional[str] = None,
    ) -> None:
        """
        Streaming JSON insert with idempotency via insertId. Uses Retry.
        """
        if not rows:
            return

        with _maybe_span("bq.insert_rows_json") as span:
            table_id = f"{self.config.project_id}.{self.config.dataset}.{table}"
            payload = []
            for r in rows:
                record = {k: _serialize_for_json(v) for k, v in r.items()}
                entry: Dict[str, Any] = {"json": record}
                if add_insert_ids:
                    entry["insertId"] = _gen_insert_id()
                payload.append(entry)

            if span:
                span.set_attribute("bq.table", table_id)
                span.set_attribute("bq.row_count", len(payload))
            self._logger.debug("Inserting rows", extra={"table": table_id, "rows": len(payload), "trace_id": trace_id})

            retry_policy = self._retry()
            errors = retry_policy(
                self._client.insert_rows_json
            )(table_id, payload, row_ids=None, skip_invalid_rows=skip_invalid_rows, ignore_unknown_values=ignore_unknown_values, timeout=self.config.default_timeout)

            if errors:
                # google API returns a list of per-row errors
                self._logger.error("Insert errors", extra={"table": table_id, "errors": errors, "trace_id": trace_id})
                raise BigQueryAdapterError(f"Failed to insert rows into {table_id}: {errors}")

    def load_dataframe(
        self,
        table: str,
        df: "pd.DataFrame",
        schema: Optional[Sequence[BQField]] = None,
        write_disposition: str = bigquery.WriteDisposition.WRITE_APPEND,
        create_disposition: str = bigquery.CreateDisposition.CREATE_IF_NEEDED,
    ) -> bigquery.LoadJob:
        if pd is None:
            raise BigQueryAdapterError("pandas is not available; cannot load dataframe.")
        table_id = f"{self.config.project_id}.{self.config.dataset}.{table}"
        with _maybe_span("bq.load_dataframe") as span:
            job_config = bigquery.LoadJobConfig(
                schema=list(schema) if schema else None,
                write_disposition=write_disposition,
                create_disposition=create_disposition,
                labels=self.config.labels,
            )
            if self.config.use_cmek and self.config.kms_key_name:
                job_config.destination_encryption_configuration = bigquery.EncryptionConfiguration(
                    kms_key_name=self.config.kms_key_name
                )
            if span:
                span.set_attribute("bq.table", table_id)
                span.set_attribute("bq.df_rows", len(df))
            job = self._client.load_table_from_dataframe(
                df, table_id, job_config=job_config, timeout=self.config.default_timeout
            )
            result = job.result(timeout=self.config.default_timeout)
            self._logger.info("DataFrame loaded", extra={"table": table_id, "output_rows": result.output_rows})
            return job

    # ----------------------------- Query ops -------------------------------- #

    def query(
        self,
        sql: str,
        params: Optional[Dict[str, Any]] = None,
        use_legacy_sql: bool = False,
        dry_run: bool = False,
        maximum_bytes_billed: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Parameterized query with safe named params.
        """
        with _maybe_span("bq.query") as span:
            job_config = bigquery.QueryJobConfig()
            job_config.use_legacy_sql = use_legacy_sql
            job_config.labels = self.config.labels
            if maximum_bytes_billed is not None:
                job_config.maximum_bytes_billed = maximum_bytes_billed
            if params:
                job_config.query_parameters = [
                    bigquery.ScalarQueryParameter(name, _guess_bq_type(value), value)  # type: ignore
                    for name, value in params.items()
                ]
            if dry_run:
                job_config.dry_run = True
                job_config.use_query_cache = False

            if span:
                span.set_attribute("bq.sql.length", len(sql))
            self._logger.debug("Executing query", extra={"dry_run": dry_run})

            retry_policy = self._retry()
            job = retry_policy(self._client.query)(sql, job_config=job_config, location=self.config.location)
            if dry_run:
                return []

            rows = list(job.result(timeout=self.config.default_timeout))
            result = [dict(r.items()) for r in rows]
            self._logger.info("Query complete", extra={"rowcount": len(result)})
            return result

    def merge_upsert(
        self,
        table: str,
        source_rows: Sequence[Dict[str, Any]],
        key_columns: Sequence[str],
        update_columns: Optional[Sequence[str]] = None,
        temp_table_suffix: Optional[str] = None,
    ) -> None:
        """
        Atomic upsert using MERGE. Loads rows into a temp table then merges.
        """
        if not source_rows:
            return

        dataset = self.config.dataset
        project = self.config.project_id
        base_table = f"{project}.{dataset}.{table}"
        tmp_suffix = temp_table_suffix or f"tmp_{int(time.time())}_{uuid.uuid4().hex[:8]}"
        tmp_table = f"{project}.{dataset}.{table}_{tmp_suffix}"

        with _maybe_span("bq.merge_upsert"):
            # Infer schema from destination table
            dest_tbl = self._client.get_table(base_table)
            schema = dest_tbl.schema

            # Create temp table
            tmp = bigquery.Table(tmp_table, schema=schema)
            tmp.labels = {**self.config.labels, "tmp": "true"}
            if self.config.use_cmek and self.config.kms_key_name:
                tmp.encryption_configuration = bigquery.EncryptionConfiguration(kms_key_name=self.config.kms_key_name)
            self._client.create_table(tmp, timeout=self.config.default_timeout)

            try:
                # Insert into temp
                self.insert_rows_json(table=f"{table}_{tmp_suffix}", rows=source_rows, add_insert_ids=False)

                # Build MERGE
                keys_cond = " AND ".join([f"T.{k} = S.{k}" for k in key_columns])
                all_columns = [f.name for f in schema]
                upd_cols = update_columns or [c for c in all_columns if c not in key_columns]
                set_clause = ", ".join([f"{c}=S.{c}" for c in upd_cols])
                insert_cols = ", ".join(all_columns)
                insert_vals = ", ".join([f"S.{c}" for c in all_columns])

                merge_sql = f"""
                MERGE `{base_table}` T
                USING `{tmp_table}` S
                ON {keys_cond}
                WHEN MATCHED THEN UPDATE SET {set_clause}
                WHEN NOT MATCHED THEN INSERT ({insert_cols}) VALUES ({insert_vals})
                """
                self.query(merge_sql)
            finally:
                # Drop temp
                with contextlib.suppress(Exception):
                    self._client.delete_table(tmp_table, not_found_ok=True)

    # ----------------------------- Audit ------------------------------------ #

    def audit_log(self, action: str, subject: str, details: Dict[str, Any]) -> None:
        """
        Write audit event into configured audit table or fallback logger.
        """
        event = {
            "ts": _utcnow_iso(),
            "action": action,
            "subject": subject,
            "details": details,
        }
        if self.config.audit_table:
            dataset, table = self._split_table_ref(self.config.audit_table)
            self.insert_rows_json(table=table, rows=[event])
        else:
            self._logger.info("AUDIT", extra=event)

    # --------------------------- Async wrappers ----------------------------- #

    async def aensure_dataset(self) -> bigquery.Dataset:
        return await self._run_async(self.ensure_dataset)

    async def aensure_table(self, *args, **kwargs) -> bigquery.Table:
        return await self._run_async(self.ensure_table, *args, **kwargs)

    async def ainsert_rows_json(self, *args, **kwargs) -> None:
        return await self._run_async(self.insert_rows_json, *args, **kwargs)

    async def aload_dataframe(self, *args, **kwargs) -> bigquery.LoadJob:
        return await self._run_async(self.load_dataframe, *args, **kwargs)

    async def aquery(self, *args, **kwargs) -> List[Dict[str, Any]]:
        return await self._run_async(self.query, *args, **kwargs)

    async def amerge_upsert(self, *args, **kwargs) -> None:
        return await self._run_async(self.merge_upsert, *args, **kwargs)

    async def aaudit_log(self, *args, **kwargs) -> None:
        return await self._run_async(self.audit_log, *args, **kwargs)

    # --------------------------- Healthcheck -------------------------------- #

    def healthcheck(self) -> Dict[str, Any]:
        """
        Lightweight healthcheck: get dataset metadata and return status.
        """
        with _maybe_span("bq.healthcheck"):
            status = {"ok": True, "ts": _utcnow_iso()}
            try:
                ds = self._client.get_dataset(f"{self.config.project_id}.{self.config.dataset}")
                status["dataset"] = ds.full_dataset_id
                status["location"] = ds.location
            except Exception as e:
                status["ok"] = False
                status["error"] = str(e)
            return status

    # ---------------------------- Internals --------------------------------- #

    def _split_table_ref(self, full: str) -> Tuple[str, str]:
        """
        Accepts "dataset.table" or "project.dataset.table"
        Returns (dataset, table) scoped to current project if needed.
        """
        parts = full.split(".")
        if len(parts) == 2:
            return parts[0], parts[1]
        if len(parts) == 3:
            return parts[1], parts[2]
        raise ValueError(f"Invalid table ref: {full}")

    def _run_async(self, fn, *args, **kwargs):
        # Lazily import asyncio to avoid mandatory dependency in sync-only workflows
        import asyncio  # local import by design
        loop = asyncio.get_event_loop()
        return loop.run_in_executor(self._executor, lambda: fn(*args, **kwargs))


def _guess_bq_type(value: Any) -> str:
    if isinstance(value, bool):
        return "BOOL"
    if isinstance(value, int):
        return "INT64"
    if isinstance(value, float):
        return "FLOAT64"
    if isinstance(value, datetime):
        return "TIMESTAMP"
    return "STRING"
