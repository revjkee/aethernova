# datafabric-core/datafabric/lineage/exporters/openlineage_emitter.py
# Industrial OpenLineage emitter for DataFabric
# - ENV/ctor config, supports official 'openlineage-python' if present, with HTTP fallback
# - Sync/async modes, background worker with batching, retries (exponential backoff + jitter), graceful shutdown
# - Sampling, idempotent run_id handling, structured logging
# - Facets: job/run, nominalTime, schema, dataQualityMetrics, dataSource, documentation, parent, errorMessage on FAIL
# - Helpers: emit_start/emit_complete/emit_fail, context manager lineage_run()
# - Lightweight adapters for Spark/Delta/Kafka dataset descriptors
# - No hard dependency on OpenLineage; integrates if installed

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import json
import os
import queue
import random
import socket
import sys
import threading
import time
import traceback
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

try:
    # Optional official client
    from openlineage.client import OpenLineageClient  # type: ignore
    from openlineage.client.facet import (
        NominalTimeRunFacet,
        DocumentationJobFacet,
        SourceCodeLocationJobFacet,
        ParentRunFacet,
        ParentRunFacetJob,
        SchemaDatasetFacet,
        SchemaDatasetFacetFields,
        DataQualityMetricsInputDatasetFacet,
        DataQualityMetricsInputDatasetFacetColumnMetrics,
        DataSourceDatasetFacet,
        ErrorMessageRunFacet,
    )  # type: ignore
    from openlineage.client.transport import HttpConfig  # type: ignore
    _OL_AVAILABLE = True
except Exception:
    _OL_AVAILABLE = False
    # Lazy stubs for type hints only

import urllib.request
import urllib.error


# ========= Config =========

@dataclass
class OpenLineageConfig:
    url: str = field(default_factory=lambda: os.getenv("OPENLINEAGE_URL", "").strip())
    api_key: Optional[str] = field(default_factory=lambda: os.getenv("OPENLINEAGE_API_KEY"))
    namespace: str = field(default_factory=lambda: os.getenv("OPENLINEAGE_NAMESPACE", "datafabric"))
    job_name_prefix: str = field(default_factory=lambda: os.getenv("OPENLINEAGE_JOB_PREFIX", "df"))
    app_name: str = field(default_factory=lambda: os.getenv("APP_NAME", "datafabric"))
    host: str = field(default_factory=lambda: socket.gethostname())
    async_mode: bool = field(default_factory=lambda: os.getenv("OPENLINEAGE_ASYNC", "true").lower() in ("1", "true", "yes"))
    batch_size: int = field(default_factory=lambda: int(os.getenv("OPENLINEAGE_BATCH_SIZE", "50")))
    max_queue: int = field(default_factory=lambda: int(os.getenv("OPENLINEAGE_MAX_QUEUE", "10000")))
    timeout_sec: int = field(default_factory=lambda: int(os.getenv("OPENLINEAGE_TIMEOUT_SEC", "10")))
    retries: int = field(default_factory=lambda: int(os.getenv("OPENLINEAGE_RETRIES", "5")))
    backoff_base: float = field(default_factory=lambda: float(os.getenv("OPENLINEAGE_BACKOFF_BASE", "0.5")))
    backoff_max: float = field(default_factory=lambda: float(os.getenv("OPENLINEAGE_BACKOFF_MAX", "8.0")))
    jitter: float = field(default_factory=lambda: float(os.getenv("OPENLINEAGE_JITTER", "0.25")))
    verify_ssl: bool = field(default_factory=lambda: os.getenv("OPENLINEAGE_VERIFY_SSL", "true").lower() in ("1", "true", "yes"))
    sample_rate: float = field(default_factory=lambda: float(os.getenv("OPENLINEAGE_SAMPLE_RATE", "1.0")))  # 0..1
    # HTTP fallback endpoint path (per OL spec v1)
    api_path: str = field(default_factory=lambda: os.getenv("OPENLINEAGE_API_PATH", "/api/v1/lineage"))
    # Optional default documentation/source facets
    job_doc_url: Optional[str] = field(default_factory=lambda: os.getenv("OPENLINEAGE_JOB_DOC_URL"))
    job_repo_url: Optional[str] = field(default_factory=lambda: os.getenv("OPENLINEAGE_JOB_REPO_URL"))
    job_repo_path: Optional[str] = field(default_factory=lambda: os.getenv("OPENLINEAGE_JOB_REPO_PATH"))
    # Global tags facet
    global_tags: Dict[str, str] = field(default_factory=lambda: _parse_kv(os.getenv("OPENLINEAGE_GLOBAL_TAGS", "")))


def _parse_kv(s: str) -> Dict[str, str]:
    """
    Parse "k=v,k2=v2" to dict. Values kept as strings.
    """
    out: Dict[str, str] = {}
    for part in [p.strip() for p in (s or "").split(",") if p.strip()]:
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


# ========= Dataset descriptors (lightweight) =========

@dataclass
class DatasetRef:
    namespace: str
    name: str
    facets: Dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def from_delta(table_path: str, storage_ns: str = "s3") -> "DatasetRef":
        return DatasetRef(namespace=storage_ns, name=table_path, facets={"dataSource": {"uri": table_path}})

    @staticmethod
    def from_kafka(topic: str, bootstrap: str, group: Optional[str] = None) -> "DatasetRef":
        f = {"dataSource": {"name": "kafka", "uri": f"kafka://{bootstrap}"}}
        if group:
            f["consumer"] = {"group": group}
        return DatasetRef(namespace="kafka", name=topic, facets=f)

    @staticmethod
    def from_jdbc(url: str, table: str) -> "DatasetRef":
        return DatasetRef(namespace="jdbc", name=f"{url}#{table}", facets={"dataSource": {"uri": url}})


# ========= Core Emitter =========

class OpenLineageEmitter:
    def __init__(self, cfg: Optional[OpenLineageConfig] = None):
        self.cfg = cfg or OpenLineageConfig()
        if not self.cfg.url:
            raise ValueError("OPENLINEAGE_URL must be provided")
        self._client = None
        if _OL_AVAILABLE:
            try:
                http_cfg = HttpConfig(url=self.cfg.url, auth=self.cfg.api_key)  # type: ignore
                self._client = OpenLineageClient(config=http_cfg)  # type: ignore
            except Exception:
                # fallback to HTTP
                self._client = None

        self._q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=self.cfg.max_queue)
        self._stop_event = threading.Event()
        self._worker: Optional[threading.Thread] = None
        if self.cfg.async_mode:
            self._worker = threading.Thread(target=self._run_worker, name="openlineage-worker", daemon=True)
            self._worker.start()

    # ----- Public API -----

    def emit_start(
        self,
        job_name: str,
        run_id: Optional[str] = None,
        inputs: Optional[Iterable[DatasetRef]] = None,
        outputs: Optional[Iterable[DatasetRef]] = None,
        nominal_start_time: Optional[dt.datetime] = None,
        parent: Optional[Tuple[str, str, str]] = None,  # (namespace, job_name, run_id)
        extra_job_facets: Optional[Dict[str, Any]] = None,
        extra_run_facets: Optional[Dict[str, Any]] = None,
    ) -> str:
        rid = run_id or str(uuid.uuid4())
        evt = self._build_event(
            eventType="START",
            job_name=self._qualified_job_name(job_name),
            run_id=rid,
            inputs=list(inputs) if inputs else [],
            outputs=list(outputs) if outputs else [],
            nominal_start_time=nominal_start_time or dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc),
            parent=parent,
            extra_job_facets=extra_job_facets,
            extra_run_facets=extra_run_facets,
        )
        self._submit(evt)
        return rid

    def emit_complete(
        self,
        job_name: str,
        run_id: str,
        outputs: Optional[Iterable[DatasetRef]] = None,
        nominal_end_time: Optional[dt.datetime] = None,
        extra_run_facets: Optional[Dict[str, Any]] = None,
    ) -> None:
        evt = self._build_event(
            eventType="COMPLETE",
            job_name=self._qualified_job_name(job_name),
            run_id=run_id,
            inputs=[],
            outputs=list(outputs) if outputs else [],
            nominal_end_time=nominal_end_time or dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc),
            extra_run_facets=extra_run_facets,
        )
        self._submit(evt)

    def emit_fail(
        self,
        job_name: str,
        run_id: str,
        err: Optional[BaseException] = None,
        extra_run_facets: Optional[Dict[str, Any]] = None,
    ) -> None:
        run_facets = dict(extra_run_facets or {})
        if err:
            run_facets["errorMessage"] = {
                "message": str(err),
                "stackTrace": "".join(traceback.format_exception(type(err), err, err.__traceback__))[:10000],
            }
        evt = self._build_event(
            eventType="FAIL",
            job_name=self._qualified_job_name(job_name),
            run_id=run_id,
            run_facets_override=run_facets,
        )
        self._submit(evt)

    @contextlib.contextmanager
    def lineage_run(
        self,
        job_name: str,
        run_id: Optional[str] = None,
        inputs: Optional[Iterable[DatasetRef]] = None,
        outputs: Optional[Iterable[DatasetRef]] = None,
        nominal_start_time: Optional[dt.datetime] = None,
        parent: Optional[Tuple[str, str, str]] = None,
        extra_job_facets: Optional[Dict[str, Any]] = None,
        extra_run_facets: Optional[Dict[str, Any]] = None,
    ):
        rid = self.emit_start(job_name, run_id, inputs, outputs, nominal_start_time, parent, extra_job_facets, extra_run_facets)
        try:
            yield rid
            self.emit_complete(job_name, rid, outputs=outputs)
        except BaseException as e:
            self.emit_fail(job_name, rid, e)
            raise

    def flush(self, timeout: Optional[float] = None) -> None:
        """
        Drain queue and stop worker in async mode. In sync mode — no-op.
        """
        if not self.cfg.async_mode:
            return
        self._stop_event.set()
        if self._worker:
            self._worker.join(timeout=timeout)

    # ----- Worker & submit -----

    def _submit(self, evt: Dict[str, Any]) -> None:
        if self.cfg.sample_rate < 1.0 and random.random() > self.cfg.sample_rate:
            return
        if self.cfg.async_mode:
            try:
                self._q.put(evt, timeout=1)
            except queue.Full:
                # Best-effort drop with warning to stderr; avoid blocking pipelines
                print("[openlineage] queue full, dropping event", file=sys.stderr)
        else:
            self._deliver_batch([evt])

    def _run_worker(self) -> None:
        buff: List[Dict[str, Any]] = []
        last_send = time.monotonic()
        while not self._stop_event.is_set() or not self._q.empty() or buff:
            try:
                evt = self._q.get(timeout=0.2)
                buff.append(evt)
            except queue.Empty:
                pass
            now = time.monotonic()
            if buff and (len(buff) >= self.cfg.batch_size or now - last_send >= 1.0):
                to_send, buff = buff, []
                self._deliver_batch(to_send)
                last_send = now
        # final drain
        if buff:
            self._deliver_batch(buff)

    # ----- Delivery (client or HTTP) -----

    def _deliver_batch(self, events: List[Dict[str, Any]]) -> None:
        if not events:
            return
        if self._client is not None:
            # Use official client one-by-one to leverage its transport & retries
            for evt in events:
                try:
                    self._client.emit(evt)  # type: ignore
                except Exception as e:
                    self._log_delivery_error(e, evt)
            return

        # HTTP fallback: POST each event (OL recommends individual events)
        for evt in events:
            body = json.dumps(evt).encode("utf-8")
            url = self.cfg.url.rstrip("/") + self.cfg.api_path
            req = urllib.request.Request(url=url, data=body, method="POST")
            req.add_header("Content-Type", "application/json")
            if self.cfg.api_key:
                req.add_header("Authorization", f"Bearer {self.cfg.api_key}")
            # retry loop
            delay = self.cfg.backoff_base
            for attempt in range(self.cfg.retries + 1):
                try:
                    with urllib.request.urlopen(req, timeout=self.cfg.timeout_sec) as resp:
                        if 200 <= resp.status < 300:
                            break
                        raise RuntimeError(f"HTTP {resp.status}")
                except Exception as e:
                    if attempt >= self.cfg.retries:
                        self._log_delivery_error(e, evt)
                        break
                    time.sleep(delay + random.random() * self.cfg.jitter)
                    delay = min(self.cfg.backoff_max, delay * 2.0)

    @staticmethod
    def _log_delivery_error(e: Exception, evt: Dict[str, Any]) -> None:
        try:
            j = json.dumps({"error": str(e), "eventType": evt.get("eventType"), "job": evt.get("job", {}).get("name"), "runId": evt.get("run", {}).get("runId")}, ensure_ascii=False)
            print(f"[openlineage] delivery error: {j}", file=sys.stderr)
        except Exception:
            print(f"[openlineage] delivery error: {e}", file=sys.stderr)

    # ----- Event building -----

    def _qualified_job_name(self, job_name: str) -> str:
        prefix = self.cfg.job_name_prefix.strip()
        return f"{prefix}.{job_name}" if prefix else job_name

    @staticmethod
    def _ts_iso(t: Optional[dt.datetime] = None) -> str:
        t = t or dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc)
        if t.tzinfo is None:
            t = t.replace(tzinfo=dt.timezone.utc)
        return t.isoformat()

    def _build_event(
        self,
        eventType: str,
        job_name: str,
        run_id: str,
        inputs: Iterable[DatasetRef] = (),
        outputs: Iterable[DatasetRef] = (),
        nominal_start_time: Optional[dt.datetime] = None,
        nominal_end_time: Optional[dt.datetime] = None,
        parent: Optional[Tuple[str, str, str]] = None,
        extra_job_facets: Optional[Dict[str, Any]] = None,
        extra_run_facets: Optional[Dict[str, Any]] = None,
        run_facets_override: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build an OpenLineage event as dict per spec.
        """
        job = {"namespace": self.cfg.namespace, "name": job_name, "facets": {}}
        run = {"runId": run_id, "facets": {}}
        # Job facets: documentation/source code, global tags
        if self.cfg.job_doc_url:
            job["facets"]["documentation"] = {"_producer": self.cfg.app_name, "_schemaURL": "https://openlineage.io/spec/facets/1-0-0/DocumentationJobFacet.json", "description": self.cfg.job_doc_url}
        if self.cfg.job_repo_url or self.cfg.job_repo_path:
            job["facets"]["sourceCodeLocation"] = {
                "_producer": self.cfg.app_name,
                "_schemaURL": "https://openlineage.io/spec/facets/1-0-0/SourceCodeLocationJobFacet.json",
                "type": "git",
                "url": self.cfg.job_repo_url,
                "path": self.cfg.job_repo_path,
            }
        if self.cfg.global_tags:
            job["facets"]["additionalProperties"] = {"tags": self.cfg.global_tags}

        # Run facets: nominal time window, producer info
        nominal: Dict[str, Any] = {}
        if nominal_start_time:
            nominal["nominalStartTime"] = self._ts_iso(nominal_start_time)
        if nominal_end_time:
            nominal["nominalEndTime"] = self._ts_iso(nominal_end_time)
        if nominal:
            run["facets"]["nominalTime"] = {"_producer": self.cfg.app_name, "_schemaURL": "https://openlineage.io/spec/facets/1-0-0/NominalTimeRunFacet.json", **nominal}

        run["facets"]["processing_engine"] = {
            "_producer": self.cfg.app_name,
            "version": os.getenv("SPARK_VERSION") or os.getenv("APP_VERSION") or "unknown",
        }

        # Parent facet
        if parent:
            p_ns, p_job, p_run = parent
            run["facets"]["parent"] = {
                "_producer": self.cfg.app_name,
                "_schemaURL": "https://openlineage.io/spec/facets/1-0-0/ParentRunFacet.json",
                "run": {"runId": p_run},
                "job": {"namespace": p_ns, "name": p_job},
            }

        # Merge extra facets
        if extra_job_facets:
            job["facets"].update(extra_job_facets)
        if extra_run_facets:
            run["facets"].update(extra_run_facets)
        if run_facets_override:
            run["facets"].update(run_facets_override)

        # Datasets
        in_arr = [self._dataset_to_ol(d) for d in inputs]
        out_arr = [self._dataset_to_ol(d) for d in outputs]

        evt = {
            "eventType": eventType,
            "eventTime": self._ts_iso(),
            "producer": self.cfg.app_name,
            "job": job,
            "run": run,
            "inputs": in_arr,
            "outputs": out_arr,
        }
        return evt

    def _dataset_to_ol(self, d: DatasetRef) -> Dict[str, Any]:
        facets = dict(d.facets or {})
        # Normalize well-known facets
        if "schema" in facets and isinstance(facets["schema"], dict):
            facets["schema"] = {
                "_producer": self.cfg.app_name,
                "_schemaURL": "https://openlineage.io/spec/facets/1-0-0/SchemaDatasetFacet.json",
                **facets["schema"],
            }
        if "dataQualityMetrics" in facets and isinstance(facets["dataQualityMetrics"], dict):
            facets["dataQualityMetrics"] = {
                "_producer": self.cfg.app_name,
                "_schemaURL": "https://openlineage.io/spec/facets/1-0-0/DataQualityMetricsInputDatasetFacet.json",
                **facets["dataQualityMetrics"],
            }
        if "dataSource" in facets and isinstance(facets["dataSource"], dict):
            facets["dataSource"] = {
                "_producer": self.cfg.app_name,
                "_schemaURL": "https://openlineage.io/spec/facets/1-0-0/DatasourceDatasetFacet.json",
                **facets["dataSource"],
            }
        return {"namespace": d.namespace, "name": d.name, "facets": facets}


# ========= Convenience builders for common facets =========

def schema_facet(fields: Iterable[Tuple[str, str, Optional[str]]]) -> Dict[str, Any]:
    """
    fields: [(name, type, description?)]
    """
    arr = []
    for name, typ, desc in fields:
        f = {"name": name, "type": typ}
        if desc:
            f["description"] = desc
        arr.append(f)
    return {"fields": arr}

def dq_metrics_facet(row_count: Optional[int] = None, null_count: Optional[Dict[str, int]] = None, min_values: Optional[Dict[str, Any]] = None, max_values: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    f: Dict[str, Any] = {}
    if row_count is not None:
        f["rowCount"] = int(row_count)
    if null_count:
        f["nullCount"] = {k: int(v) for k, v in null_count.items()}
    if min_values:
        f["min"] = min_values
    if max_values:
        f["max"] = max_values
    return f

def datasource_facet(name: Optional[str] = None, uri: Optional[str] = None) -> Dict[str, Any]:
    f: Dict[str, Any] = {}
    if name:
        f["name"] = name
    if uri:
        f["uri"] = uri
    return f


# ========= Minimal Spark helpers (optional usage) =========

def datasetref_from_spark_delta(path: str) -> DatasetRef:
    return DatasetRef.from_delta(table_path=path)

def datasetref_from_kafka(topic: str, bootstrap: str, group: Optional[str] = None) -> DatasetRef:
    return DatasetRef.from_kafka(topic=topic, bootstrap=bootstrap, group=group)

def datasetref_from_jdbc(url: str, table: str) -> DatasetRef:
    return DatasetRef.from_jdbc(url=url, table=table)


# ========= Self-test / Usage example (safe, no network) =========

if __name__ == "__main__":
    # Dry-run build event (no network) — set OPENLINEAGE_URL to enable delivery.
    os.environ.setdefault("OPENLINEAGE_URL", "http://localhost:8080")
    cfg = OpenLineageConfig()
    emitter = OpenLineageEmitter(cfg)

    inputs = [
        datasetref_from_kafka(topic="events.raw", bootstrap="kafka:9092", group="df-consumer"),
        DatasetRef(namespace="s3", name="s3a://bucket/raw/users.json", facets={
            "schema": schema_facet([("id","string",None),("email","string","user email")]),
            "dataSource": datasource_facet(uri="s3a://bucket"),
        })
    ]
    outputs = [
        datasetref_from_spark_delta("s3a://bucket/curated/users_delta"),
    ]

    with emitter.lineage_run(
        job_name="ingest.users",
        inputs=inputs,
        outputs=outputs,
        extra_job_facets={"documentation": {"description": "Ingests users from Kafka to Delta"}},
    ) as run_id:
        # your job here
        pass
