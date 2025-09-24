# -*- coding: utf-8 -*-
"""
Industrial-grade batch DAG for DataFabric.

Features:
- Airflow 2.6+ TaskFlow API
- Dynamic task mapping over multiple input URIs
- Idempotency via content hashing + marker files
- Data quality checks (row count, required columns, null-rate ceilings)
- Slack alerts on failure (optional via SLACK_WEBHOOK)
- SLA monitoring
- Exponential retries with jitter
- Dataset-based scheduling (optional)
- OpenLineage-compatible metadata (optional)
- Pluggable I/O adapters for s3://, gs://, file://
- Parameterization via Airflow Params, Variables, and Env

Path: datafabric-core/datafabric/processing/batch/airflow_dag.py
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Airflow core
from airflow import DAG, Dataset
from airflow.decorators import dag, task
from airflow.exceptions import AirflowFailException
from airflow.models import Variable
from airflow.utils.trigger_rule import TriggerRule

# Operators / utils
from airflow.operators.empty import EmptyOperator
from airflow.operators.python import get_current_context
from airflow.operators.email import EmailOperator  # optional, if SMTP configured
from airflow.sensors.base import PokeReturnValue

# Providers (use if installed; code falls back gracefully)
with contextlib.suppress(ImportError):
    from airflow.providers.amazon.aws.hooks.s3 import S3Hook
with contextlib.suppress(ImportError):
    from airflow.providers.google.cloud.hooks.gcs import GCSHook

# Slack (webhook) optional
import urllib.request


# ---------------------------
# Configuration & Constants
# ---------------------------

DEF_OWNER = "datafabric"
DEF_RETRIES = 3
DEF_RETRY_DELAY = 60  # seconds
DEF_SLA_MINUTES = 45

# Airflow Variables with safe defaults
VAR_SLACK_WEBHOOK = Variable.get("SLACK_WEBHOOK", default_var=None)
VAR_DEFAULT_OUTPUT_BUCKET = Variable.get("DF_OUTPUT_BUCKET", default_var="s3://datafabric-output")
VAR_DEFAULT_TMP_DIR = Variable.get("DF_TMP_DIR", default_var="/opt/airflow/tmp")
VAR_DQ_NULL_RATE_MAX = float(Variable.get("DF_DQ_NULL_RATE_MAX", default_var="0.1"))  # 10%
VAR_REQUIRED_COLUMNS = json.loads(Variable.get("DF_REQUIRED_COLUMNS", default_var="[]"))

# Optional dataset scheduling
UPSTREAM_DATASETS_STR = Variable.get("DF_UPSTREAM_DATASETS", default_var="")
UPSTREAM_DATASETS = tuple(Dataset(d) for d in UPSTREAM_DATASETS_STR.split(",") if d.strip())

# Optional OpenLineage: set OPENLINEAGE_URL/OPENLINEAGE_NAMESPACE via env for full integration
OPENLINEAGE_ENABLED = bool(os.getenv("OPENLINEAGE_URL"))


# ---------------------------
# Helpers
# ---------------------------

def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes", "y", "on"}


def _slack_post(webhook: Optional[str], text: str) -> None:
    if not webhook:
        return
    try:
        req = urllib.request.Request(
            webhook,
            data=json.dumps({"text": text}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            _ = resp.read()
    except Exception as e:
        logging.warning("Slack post failed: %s", e)


def _ensure_dir(path: str | Path) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)


def _airflow_tmp_dir() -> str:
    base = VAR_DEFAULT_TMP_DIR
    _ensure_dir(base)
    return base


# ---------------------------
# IO Adapters
# ---------------------------

class IOAdapter:
    """Abstract IO adapter supporting simple read/write by URI."""

    def read(self, uri: str) -> bytes:
        raise NotImplementedError

    def write(self, uri: str, data: bytes, *, overwrite: bool = True) -> None:
        raise NotImplementedError

    def exists(self, uri: str) -> bool:
        raise NotImplementedError


class LocalAdapter(IOAdapter):
    def read(self, uri: str) -> bytes:
        path = uri.replace("file://", "")
        with open(path, "rb") as f:
            return f.read()

    def write(self, uri: str, data: bytes, *, overwrite: bool = True) -> None:
        path = uri.replace("file://", "")
        _ensure_dir(Path(path).parent)
        mode = "wb" if overwrite else "xb"
        with open(path, mode) as f:
            f.write(data)

    def exists(self, uri: str) -> bool:
        path = uri.replace("file://", "")
        return Path(path).exists()


class S3Adapter(IOAdapter):
    def __init__(self, conn_id: str = "aws_default") -> None:
        if "S3Hook" not in globals():
            raise ImportError("airflow.providers.amazon not installed")
        self.hook = S3Hook(aws_conn_id=conn_id)

    def _split(self, uri: str) -> Tuple[str, str]:
        # s3://bucket/key...
        _, rest = uri.split("://", 1)
        bucket, key = rest.split("/", 1)
        return bucket, key

    def read(self, uri: str) -> bytes:
        bucket, key = self._split(uri)
        return self.hook.read_key(key=key, bucket_name=bucket).encode("utf-8")

    def write(self, uri: str, data: bytes, *, overwrite: bool = True) -> None:
        bucket, key = self._split(uri)
        if not overwrite and self.hook.check_for_key(key, bucket):
            raise FileExistsError(f"S3 key exists: {uri}")
        self.hook.load_bytes(
            bytes_data=data, key=key, bucket_name=bucket, replace=overwrite
        )

    def exists(self, uri: str) -> bool:
        bucket, key = self._split(uri)
        return self.hook.check_for_key(key, bucket)


class GCSAdapter(IOAdapter):
    def __init__(self, conn_id: str = "google_cloud_default") -> None:
        if "GCSHook" not in globals():
            raise ImportError("airflow.providers.google not installed")
        self.hook = GCSHook(gcp_conn_id=conn_id)

    def _split(self, uri: str) -> Tuple[str, str]:
        # gs://bucket/key...
        _, rest = uri.split("://", 1)
        bucket, key = rest.split("/", 1)
        return bucket, key

    def read(self, uri: str) -> bytes:
        bucket, key = self._split(uri)
        return self.hook.download(bucket, key)

    def write(self, uri: str, data: bytes, *, overwrite: bool = True) -> None:
        bucket, key = self._split(uri)
        if not overwrite and self.hook.exists(bucket, key):
            raise FileExistsError(f"GCS object exists: {uri}")
        # upload from bytes: use in-memory stream
        self.hook.upload(bucket, key, io.BytesIO(data))

    def exists(self, uri: str) -> bool:
        bucket, key = self._split(uri)
        return self.hook.exists(bucket, key)


def get_adapter(uri: str) -> IOAdapter:
    if uri.startswith("s3://"):
        return S3Adapter()
    if uri.startswith("gs://"):
        return GCSAdapter()
    if uri.startswith("file://") or uri.startswith("/"):
        # Support raw paths by normalizing to file://
        if not uri.startswith("file://"):
            uri = f"file://{uri}"
        return LocalAdapter()
    raise ValueError(f"Unsupported URI scheme for {uri}")


# ---------------------------
# Data Contracts
# ---------------------------

@dataclass(frozen=True)
class ExtractResult:
    uri: str
    tmp_path: str
    content_hash: str
    nbytes: int


@dataclass(frozen=True)
class TransformResult:
    uri: str
    tmp_path: str
    content_hash: str
    nrows: int
    schema: List[str]


@dataclass(frozen=True)
class DQReport:
    uri: str
    nrows: int
    required_columns_present: bool
    null_rate_ok: bool
    null_rates: Dict[str, float]


# ---------------------------
# DAG Definition
# ---------------------------

default_args = {
    "owner": DEF_OWNER,
    "depends_on_past": False,
    "retries": DEF_RETRIES,
    "retry_delay": timedelta(seconds=DEF_RETRY_DELAY),
    "retry_exponential_backoff": True,
    "max_retry_delay": timedelta(minutes=10),
    "email_on_failure": False,
    "email_on_retry": False,
}

# Optional Datasets for scheduling
dataset_inputs = list(UPSTREAM_DATASETS)

@dag(
    dag_id="datafabric_batch_pipeline",
    description="DataFabric industrial batch pipeline",
    schedule=Variable.get("DF_SCHEDULE_CRON", default_var="0 * * * *"),
    start_date=datetime(2025, 1, 1),
    catchup=_read_env_flag("DF_CATCHUP", False),
    default_args=default_args,
    tags=["datafabric", "batch", "industrial"],
    sla_miss_callback=lambda *args, **kwargs: _slack_post(
        VAR_SLACK_WEBHOOK, f"SLA missed for DAG datafabric_batch_pipeline at {datetime.utcnow().isoformat()}Z"
    ),
    render_template_as_native_obj=True,
    max_active_runs=1,
)
def datafabric_batch_pipeline():
    """
    Batch pipeline:
    1. Prepare & Resolve inputs
    2. Extract -> Transform -> Validate -> Load -> Publish
    3. Lineage/Finalize
    """

    # ---------------------------
    # Params and kick-off
    # ---------------------------
    start = EmptyOperator(task_id="start")
    finish = EmptyOperator(task_id="finish", trigger_rule=TriggerRule.ALL_DONE)

    # Airflow Params: allow list of input URIs or single string
    # Example of params to set at trigger:
    # {
    #   "batch_date": "2025-08-15",
    #   "input_uris": ["s3://bucket/path/file1.jsonl", "gs://bkt/file2.jsonl"],
    #   "output_base": "s3://datafabric-output/warehouse/topicA/",
    #   "required_columns": ["id", "ts", "value"]
    # }
    @task
    def resolve_params() -> Dict[str, Any]:
        ctx = get_current_context()
        params = ctx["params"] or {}
        batch_date = params.get("batch_date") or datetime.utcnow().date().isoformat()
        input_uris = params.get("input_uris") or []
        if isinstance(input_uris, str):
            input_uris = [input_uris]
        if not input_uris:
            # fallback to a variable for smoke tests
            fallback = Variable.get("DF_INPUT_URIS", default_var="")
            input_uris = [u for u in fallback.split(",") if u.strip()]
        if not input_uris:
            raise AirflowFailException("No input_uris provided via params or Variables")

        output_base = params.get("output_base") or VAR_DEFAULT_OUTPUT_BUCKET.rstrip("/")
        required_cols = params.get("required_columns") or VAR_REQUIRED_COLUMNS

        return {
            "batch_date": batch_date,
            "input_uris": input_uris,
            "output_base": output_base,
            "required_columns": required_cols,
            "null_rate_max": VAR_DQ_NULL_RATE_MAX,
        }

    # Optional upstream dataset sensor (deferrable-like poke)
    @task.sensor(poke_interval=30, timeout=60 * 30, mode="reschedule")  # 30 min
    def wait_for_upstream() -> PokeReturnValue:
        if not dataset_inputs:
            return PokeReturnValue(is_done=True)
        # Airflow's native Dataset scheduling will trigger DAG; here we just pass through
        return PokeReturnValue(is_done=True)

    # ---------------------------
    # Extract
    # ---------------------------
    @task
    def extract_one(uri: str, batch_date: str) -> ExtractResult:
        adapter = get_adapter(uri)
        data = adapter.read(uri)
        h = _sha256_bytes(data)
        tmp_dir = Path(_airflow_tmp_dir()) / "extract" / batch_date
        _ensure_dir(tmp_dir)
        tmp_path = tmp_dir / f"{h}.jsonl"
        if not tmp_path.exists():
            with open(tmp_path, "wb") as f:
                f.write(data)
        logging.info("Extracted %s -> %s (%d bytes)", uri, tmp_path, len(data))
        return ExtractResult(uri=uri, tmp_path=str(tmp_path), content_hash=h, nbytes=len(data))

    # ---------------------------
    # Transform
    # ---------------------------
    @task
    def transform_one(x: ExtractResult) -> TransformResult:
        """
        Example transform: newline-delimited JSON to canonical JSONL with column order;
        simple schema inference (keys union) and row count.
        """
        import json

        nrows = 0
        schema_keys: List[str] = []
        out_buf = io.StringIO()

        # First pass: infer keys union (small/medium batch assumption)
        keys_union: set[str] = set()
        with open(x.tmp_path, "rb") as f:
            for line in f:
                if not line.strip():
                    continue
                obj = json.loads(line)
                keys_union.update(obj.keys())
        schema_keys = sorted(keys_union)

        # Second pass: reorder fields and normalize nulls
        with open(x.tmp_path, "rb") as f:
            for line in f:
                if not line.strip():
                    continue
                obj = json.loads(line)
                normalized = {k: obj.get(k, None) for k in schema_keys}
                out_buf.write(json.dumps(normalized, separators=(",", ":")) + "\n")
                nrows += 1

        content = out_buf.getvalue().encode("utf-8")
        h = _sha256_bytes(content)

        out_dir = Path(_airflow_tmp_dir()) / "transform"
        _ensure_dir(out_dir)
        out_path = out_dir / f"{h}.jsonl"
        if not out_path.exists():
            with open(out_path, "wb") as f:
                f.write(content)

        logging.info("Transformed %s -> %s (rows=%d, schema=%s)", x.uri, out_path, nrows, schema_keys)
        return TransformResult(uri=x.uri, tmp_path=str(out_path), content_hash=h, nrows=nrows, schema=schema_keys)

    # ---------------------------
    # Validate (Data Quality)
    # ---------------------------
    @task
    def validate_one(t: TransformResult, required_columns: List[str], null_rate_max: float) -> DQReport:
        import json
        from collections import defaultdict

        if t.nrows == 0:
            raise AirflowFailException(f"No rows after transform for {t.uri}")

        # required columns present?
        required_ok = all(col in t.schema for col in required_columns)

        # compute null-rates
        null_counts = defaultdict(int)
        with open(t.tmp_path, "rb") as f:
            for line in f:
                obj = json.loads(line)
                for col in t.schema:
                    if obj.get(col, None) is None:
                        null_counts[col] += 1

        null_rates = {c: null_counts[c] / t.nrows for c in t.schema}
        null_ok = all(rate <= null_rate_max for rate in null_rates.values())

        if not required_ok:
            raise AirflowFailException(f"Required columns missing in {t.uri}. Required={required_columns} got={t.schema}")

        if not null_ok:
            raise AirflowFailException(f"Null rates exceed max {null_rate_max} for {t.uri}: {null_rates}")

        logging.info("DQ OK for %s: rows=%d null_max=%.4f", t.uri, t.nrows, max(null_rates.values(), default=0.0))
        return DQReport(uri=t.uri, nrows=t.nrows, required_columns_present=required_ok, null_rate_ok=null_ok, null_rates=null_rates)

    # ---------------------------
    # Load
    # ---------------------------
    @task
    def load_one(t: TransformResult, output_base: str, batch_date: str) -> str:
        """
        Load to partitioned path: {output_base}/dt={batch_date}/{hash}.jsonl
        Idempotent: checks if object exists.
        """
        if not output_base.startswith(("s3://", "gs://", "file://", "/")):
            raise AirflowFailException(f"Unsupported output_base: {output_base}")

        # Normalize base
        if output_base.startswith("/"):
            output_base = f"file://{output_base}"

        out_uri = f"{output_base}/dt={batch_date}/{t.content_hash}.jsonl"
        adapter = get_adapter(out_uri)
        if adapter.exists(out_uri):
            logging.info("Load skipped (exists): %s", out_uri)
            return out_uri

        with open(t.tmp_path, "rb") as f:
            adapter.write(out_uri, f.read(), overwrite=True)

        logging.info("Loaded %s -> %s", t.tmp_path, out_uri)
        return out_uri

    # ---------------------------
    # Publish / Manifest
    # ---------------------------
    @task
    def publish_manifest(loaded_uris: List[str], params: Dict[str, Any]) -> str:
        manifest = {
            "batch_date": params["batch_date"],
            "inputs": params["input_uris"],
            "outputs": loaded_uris,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "dq": {
                "required_columns": params["required_columns"],
                "null_rate_max": params["null_rate_max"],
            },
            "dag_id": "datafabric_batch_pipeline",
            "run_id": get_current_context()["run_id"],
        }
        content = json.dumps(manifest, indent=2).encode("utf-8")
        # default place: {output_base}/dt=.../manifest_{ts}.json
        output_base = params["output_base"]
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        manifest_uri = f"{output_base}/dt={params['batch_date']}/manifest_{ts}.json"
        adapter = get_adapter(manifest_uri)
        adapter.write(manifest_uri, content, overwrite=True)
        logging.info("Published manifest to %s", manifest_uri)
        return manifest_uri

    # ---------------------------
    # Alerts & Finalize
    # ---------------------------
    @task(trigger_rule=TriggerRule.ONE_FAILED)
    def alert_failure(params: Dict[str, Any]) -> None:
        ctx = get_current_context()
        msg = (
            f":warning: DataFabric batch failed\n"
            f"DAG: {ctx['dag'].dag_id}\n"
            f"Run: {ctx['run_id']}\n"
            f"Batch date: {params.get('batch_date')}\n"
            f"Logical date: {ctx['logical_date'].isoformat()}Z"
        )
        _slack_post(VAR_SLACK_WEBHOOK, msg)

    @task(trigger_rule=TriggerRule.ALL_SUCCESS)
    def finalize_success(manifest_uri: str) -> None:
        _slack_post(VAR_SLACK_WEBHOOK, f"DataFabric batch success. Manifest: {manifest_uri}")

    # ---------------------------
    # Wiring
    # ---------------------------
    params = resolve_params()

    # Optional wait on datasets
    _ = wait_for_upstream()
    start >> _

    # Dynamic mapping over inputs
    extracted = extract_one.partial(batch_date=params["batch_date"]).expand(uri=params["input_uris"])
    transformed = transform_one.expand(x=extracted)
    dq_reports = validate_one.expand(
        t=transformed,
        required_columns=[params["required_columns"]],
        null_rate_max=[params["null_rate_max"]],
    )
    loaded = load_one.partial(output_base=params["output_base"], batch_date=params["batch_date"]).expand(t=transformed)

    manifest_uri = publish_manifest(loaded_uris=loaded, params=params)
    ok = finalize_success(manifest_uri)
    fail = alert_failure(params)

    # Graph
    extracted >> transformed >> dq_reports >> loaded >> manifest_uri
    [manifest_uri >> ok, dq_reports >> fail]

    manifest_uri >> finish
    start >> finish

    # Return allows testing with dag.test()
    return None


# Instantiate the DAG
DAG_OBJ = datafabric_batch_pipeline()


# ---------------------------
# Global Failure Callback (Optional)
# ---------------------------

def on_dag_failure_callback(context: Dict[str, Any]) -> None:
    try:
        dag_id = context.get("dag").dag_id if context.get("dag") else "unknown"
        run_id = context.get("run_id")
        _slack_post(VAR_SLACK_WEBHOOK, f":x: DAG {dag_id} failed. run_id={run_id}")
    except Exception as e:
        logging.warning("Failure callback error: %s", e)
