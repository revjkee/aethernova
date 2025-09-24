from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import logging
import os
import random
import shutil
import time
import typing as t
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# Optional deps (lazy)
with contextlib.suppress(Exception):
    import boto3  # type: ignore
with contextlib.suppress(Exception):
    import psycopg  # psycopg 3 (sync)  # type: ignore

# Optional OpenTelemetry (graceful if absent)
try:
    from opentelemetry import trace  # type: ignore
    from opentelemetry.trace import Status, StatusCode  # type: ignore
except Exception:  # pragma: no cover
    trace = None
    Status = None
    StatusCode = None

logger = logging.getLogger("ov.exec.soft_delete")
logger.setLevel(logging.INFO)

# ---------- Helpers / Types ----------

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso_now() -> str:
    return now_utc().isoformat()

def otel_span(name: str):
    if trace is None:
        class _Nop:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def set_attribute(self, *a, **k): pass
            def set_status(self, *a, **k): pass
        return _Nop()
    tracer = trace.get_tracer("ov.executors")
    return tracer.start_as_current_span(name)

def sleep_seconds(sec: float) -> t.Awaitable[None]:
    return asyncio.sleep(sec)

def jittered_backoff(attempt: int, base: float = 0.25, cap: float = 5.0) -> float:
    """Exponential backoff with full jitter (AWS style)."""
    return min(cap, random.random() * (base * (2 ** attempt)))

@dataclass
class TargetPolicy:
    safe_delete: bool = True
    worm_required: bool = False
    batch_size: int = 1000
    rate_limit_per_second: int = 5000

@dataclass
class ResourceSelector:
    type: str  # s3|minio|filesystem|postgres|...
    uri: t.Optional[str] = None
    bucket: t.Optional[str] = None
    container: t.Optional[str] = None
    path_globs: t.Optional[t.List[str]] = None
    db: t.Optional[str] = None
    schema: t.Optional[str] = None
    table: t.Optional[str] = None
    where_sql: t.Optional[str] = None
    topic: t.Optional[str] = None
    labels: t.Optional[t.Dict[str, str]] = None

@dataclass
class Target:
    selector: ResourceSelector
    policy: TargetPolicy

@dataclass
class ExecResult:
    target: Target
    processed: int = 0
    skipped: int = 0
    errors: int = 0
    details: t.List[str] = dataclasses.field(default_factory=list)

@dataclass
class RunSummary:
    task_id: str
    started_at: str
    finished_at: str
    total_targets: int
    processed_total: int
    skipped_total: int
    errors_total: int
    results: t.List[ExecResult]

# ---------- Base Adapter ----------

class BaseAdapter:
    """Adapter contract for different backends."""

    def __init__(self, selector: ResourceSelector, policy: TargetPolicy, dry_run: bool = False):
        self.selector = selector
        self.policy = policy
        self.dry_run = dry_run

    async def soft_delete(self) -> ExecResult:
        raise NotImplementedError("soft_delete not implemented for this adapter")

    # Utilities
    async def _rate_limit(self, count: int) -> None:
        """Simple token bucket: sleep to respect rate_limit_per_second."""
        rps = max(1, self.policy.rate_limit_per_second)
        # naive: sleep proportional to items processed
        await sleep_seconds(count / rps)

# ---------- Filesystem Adapter ----------

class FilesystemAdapter(BaseAdapter):
    """
    Soft-delete for filesystem:
      - Move matched files to a sibling .trash directory (idempotent).
      - Create tombstone JSON with metadata.
    """

    DEFAULT_TRASH_DIR = ".trash"

    async def soft_delete(self) -> ExecResult:
        res = ExecResult(target=Target(self.selector, self.policy))
        globs = self.selector.path_globs or []
        if not globs:
            res.details.append("no path_globs provided")
            res.skipped += 1
            return res

        for pattern in globs:
            paths = list(Path("/").glob(pattern) if pattern.startswith("/") else Path.cwd().glob(pattern))
            for p in paths:
                try:
                    if not p.exists():
                        res.skipped += 1
                        continue
                    trash_dir = (p.parent / self.DEFAULT_TRASH_DIR)
                    trash_dir.mkdir(parents=True, exist_ok=True)
                    dest = trash_dir / p.name
                    tombstone = trash_dir / f"{p.name}.tombstone.json"

                    if dest.exists() and tombstone.exists():
                        res.skipped += 1
                        continue

                    if not self.dry_run:
                        shutil.move(str(p), str(dest))
                        with open(tombstone, "w", encoding="utf-8") as f:
                            json.dump(
                                {
                                    "deleted_at": iso_now(),
                                    "original_path": str(p),
                                    "reason": "soft-delete",
                                    "policy": dataclasses.asdict(self.policy),
                                },
                                f,
                            )
                    res.processed += 1
                    await self._rate_limit(1)
                except Exception as e:
                    logger.exception("filesystem soft-delete failed for %s: %s", p, e)
                    res.errors += 1
                    res.details.append(f"error:{p}:{e}")
        return res

# ---------- S3 / MinIO Adapter ----------

class S3Adapter(BaseAdapter):
    """
    Soft-delete for S3/MinIO:
      - Add tag ov:deleted=true and deleted_at timestamp (idempotent).
      - Copy object to _trash/ prefix (optional; enabled by default).
      - Write tombstone object alongside.
    Notes:
      - Requires boto3; credentials/config resolved by standard AWS env/IMDS.
    """

    TRASH_PREFIX = "_trash/"

    async def soft_delete(self) -> ExecResult:
        if "boto3" not in globals() or boto3 is None:
            raise RuntimeError("boto3 is required for s3/minio adapter")

        res = ExecResult(target=Target(self.selector, self.policy))
        bucket = self.selector.bucket
        if not bucket:
            res.details.append("bucket not provided")
            res.skipped += 1
            return res

        s3 = boto3.client("s3")
        paginator = s3.get_paginator("list_objects_v2")
        path_globs = self.selector.path_globs or ["*"]

        # Resolve prefixes from globs (simple heuristic: take substring before first wildcard)
        def prefix_from_glob(g: str) -> str:
            if "*" in g or "?" in g:
                return g.split("*", 1)[0].split("?", 1)[0]
            return g

        prefixes = list({prefix_from_glob(g) for g in path_globs})
        for prefix in prefixes:
            try:
                for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
                    for obj in page.get("Contents", []):
                        key = obj["Key"]
                        # Skip trash itself
                        if key.startswith(self.TRASH_PREFIX):
                            res.skipped += 1
                            continue

                        # Read existing tags
                        try:
                            tags_resp = s3.get_object_tagging(Bucket=bucket, Key=key)
                            tags = {t["Key"]: t["Value"] for t in tags_resp.get("TagSet", [])}
                        except Exception:
                            tags = {}

                        if tags.get("ov:deleted") == "true":
                            res.skipped += 1
                            continue

                        if not self.dry_run:
                            # 1) Tag object
                            new_tags = tags.copy()
                            new_tags["ov:deleted"] = "true"
                            new_tags["ov:deleted_at"] = iso_now()
                            tagset = [{"Key": k, "Value": v} for k, v in new_tags.items()]
                            s3.put_object_tagging(Bucket=bucket, Key=key, Tagging={"TagSet": tagset})

                            # 2) Copy to trash (idempotent)
                            dest_key = f"{self.TRASH_PREFIX}{key}"
                            s3.copy_object(
                                Bucket=bucket,
                                CopySource={"Bucket": bucket, "Key": key},
                                Key=dest_key,
                                MetadataDirective="REPLACE",
                                Metadata={"ov:soft-delete": "true", "ov:source-key": key, "ov:deleted_at": iso_now()},
                            )

                            # 3) Tombstone JSON
                            tombstone_key = f"{dest_key}.tombstone.json"
                            tombstone_body = json.dumps(
                                {
                                    "bucket": bucket,
                                    "key": key,
                                    "deleted_at": iso_now(),
                                    "policy": dataclasses.asdict(self.policy),
                                }
                            ).encode("utf-8")
                            s3.put_object(Bucket=bucket, Key=tombstone_key, Body=tombstone_body, ContentType="application/json")

                        res.processed += 1
                        await self._rate_limit(1)
            except Exception as e:
                logger.exception("s3 soft-delete failed for prefix %s: %s", prefix, e)
                res.errors += 1
                res.details.append(f"error:{prefix}:{e}")
        return res

# ---------- Postgres Adapter ----------

class PostgresAdapter(BaseAdapter):
    """
    Soft-delete for PostgreSQL:
      - UPDATE <schema>.<table> SET deleted_at = NOW() WHERE <where_sql> AND deleted_at IS NULL
      - Optional batch processing via LIMIT.
    Requires psycopg 3 and a valid connection URI in selector.uri (e.g. postgresql://user:pass@host:5432/db).
    """

    BATCH_LIMIT_DEFAULT = 5000

    async def soft_delete(self) -> ExecResult:
        if "psycopg" not in globals() or psycopg is None:
            raise RuntimeError("psycopg (v3) is required for postgres adapter")

        res = ExecResult(target=Target(self.selector, self.policy))
        if not self.selector.uri or not self.selector.table:
            res.details.append("postgres uri/table not provided")
            res.skipped += 1
            return res

        schema = self.selector.schema or "public"
        table = self.selector.table
        where = self.selector.where_sql or "TRUE"
        batch = max(1, min(self.policy.batch_size or self.BATCH_LIMIT_DEFAULT, 100000))

        # We use sync psycopg in a thread executor to avoid adding async driver complexity
        loop = asyncio.get_running_loop()
        res2 = await loop.run_in_executor(None, self._run_pg_sync, schema, table, where, batch)
        return res2

    def _run_pg_sync(self, schema: str, table: str, where: str, batch: int) -> ExecResult:
        res = ExecResult(target=Target(self.selector, self.policy))
        attempt = 0
        updated_total = 0
        try:
            with psycopg.connect(self.selector.uri) as conn:
                conn.execute("SET lock_timeout = '3s';")
                conn.execute("SET statement_timeout = '5min';")

                while True:
                    try:
                        with conn.transaction():
                            if self.dry_run:
                                # Estimate count only
                                q = f"SELECT count(1) FROM {schema}.{table} WHERE ({where}) AND deleted_at IS NULL"
                                c = conn.execute(q).fetchone()[0]
                                res.processed += int(c)
                                break

                            q = (
                                f"WITH cte AS ("
                                f"  SELECT id FROM {schema}.{table} "
                                f"  WHERE ({where}) AND deleted_at IS NULL "
                                f"  ORDER BY id "
                                f"  LIMIT {batch}"
                                f") "
                                f"UPDATE {schema}.{table} u "
                                f"SET deleted_at = NOW() AT TIME ZONE 'UTC' "
                                f"FROM cte WHERE u.id = cte.id"
                            )
                            cur = conn.execute(q)
                            upd = cur.rowcount or 0
                            updated_total += upd
                            res.processed += upd
                            if upd == 0:
                                break
                    except Exception as e:
                        # retry with backoff
                        attempt += 1
                        if attempt > 6:
                            raise
                        delay = jittered_backoff(attempt, base=0.5, cap=5.0)
                        logger.warning("pg soft-delete transient failure: %s; retry in %.2fs", e, delay)
                        time.sleep(delay)
                conn.commit()
        except Exception as e:
            logger.exception("postgres soft-delete failed: %s", e)
            res.errors += 1
            res.details.append(f"error:{e}")
        return res

# ---------- Placeholders (raise NotImplemented) ----------

class AzureBlobAdapter(BaseAdapter):
    async def soft_delete(self) -> ExecResult:
        raise NotImplementedError("azure_blob soft-delete adapter not implemented")

class GCSAdapter(BaseAdapter):
    async def soft_delete(self) -> ExecResult:
        raise NotImplementedError("gcs soft-delete adapter not implemented")

class KafkaAdapter(BaseAdapter):
    async def soft_delete(self) -> ExecResult:
        raise NotImplementedError("kafka soft-delete adapter not implemented")

class ClickHouseAdapter(BaseAdapter):
    async def soft_delete(self) -> ExecResult:
        raise NotImplementedError("clickhouse soft-delete adapter not implemented")

class ElasticsearchAdapter(BaseAdapter):
    async def soft_delete(self) -> ExecResult:
        raise NotImplementedError("elasticsearch soft-delete adapter not implemented")

# ---------- Executor ----------

class SoftDeleteExecutor:
    """
    Dispatcher that executes soft-delete for all task targets supporting safe_delete.
    Compatible with ErasureTask payload structure.
    """

    ADAPTERS: t.Dict[str, t.Type[BaseAdapter]] = {
        "filesystem": FilesystemAdapter,
        "s3": S3Adapter,
        "minio": S3Adapter,
        "postgres": PostgresAdapter,
        "azure_blob": AzureBlobAdapter,
        "gcs": GCSAdapter,
        "kafka": KafkaAdapter,
        "clickhouse": ClickHouseAdapter,
        "elasticsearch": ElasticsearchAdapter,
    }

    def __init__(self, concurrency: int = 16):
        self.concurrency = max(1, min(256, concurrency))

    async def run(self, task_payload: t.Dict[str, t.Any]) -> RunSummary:
        task_id = str(task_payload.get("id", "unknown"))
        dry_run = bool(task_payload.get("dry_run", False))
        targets_raw = task_payload.get("targets") or []
        targets: t.List[Target] = []
        for t_raw in targets_raw:
            sel = t_raw.get("selector", {})
            pol = t_raw.get("policy", {})
            target = Target(
                selector=ResourceSelector(
                    type=str(sel.get("type", "")),
                    uri=sel.get("uri"),
                    bucket=sel.get("bucket"),
                    container=sel.get("container"),
                    path_globs=sel.get("path_globs"),
                    db=sel.get("db"),
                    schema=sel.get("schema"),
                    table=sel.get("table"),
                    where_sql=sel.get("where_sql"),
                    topic=sel.get("topic"),
                    labels=sel.get("labels"),
                ),
                policy=TargetPolicy(
                    safe_delete=bool(pol.get("safe_delete", True)),
                    worm_required=bool(pol.get("worm_required", False)),
                    batch_size=int(pol.get("batch_size", 1000)),
                    rate_limit_per_second=int(pol.get("rate_limit_per_second", 5000)),
                ),
            )
            targets.append(target)

        started = iso_now()
        results: t.List[ExecResult] = []

        async def handle(target: Target) -> ExecResult:
            with otel_span("soft_delete.target") as span:
                try:
                    if span:
                        span.set_attribute("selector.type", target.selector.type)
                        span.set_attribute("policy.safe_delete", target.policy.safe_delete)
                    if not target.policy.safe_delete:
                        r = ExecResult(target=target, processed=0, skipped=1, errors=0, details=["safe_delete disabled"])
                        return r
                    adapter_cls = self.ADAPTERS.get(target.selector.type)
                    if not adapter_cls:
                        r = ExecResult(target=target, processed=0, skipped=1, errors=1, details=["no adapter"])
                        if span and Status and StatusCode:
                            span.set_status(Status(StatusCode.ERROR))
                        return r
                    adapter = adapter_cls(target.selector, target.policy, dry_run=dry_run)
                    # Per-target retries (transient)
                    attempt = 0
                    while True:
                        try:
                            res = await adapter.soft_delete()
                            if span and Status and StatusCode:
                                span.set_status(Status(StatusCode.OK))
                            return res
                        except Exception as e:
                            attempt += 1
                            if attempt > 5:
                                logger.exception("target failed permanently (%s): %s", target.selector.type, e)
                                if span and Status and StatusCode:
                                    span.set_status(Status(StatusCode.ERROR))
                                return ExecResult(target=target, errors=1, details=[f"fatal:{e}"], skipped=0, processed=0)
                            delay = jittered_backoff(attempt, base=0.5, cap=4.0)
                            logger.warning("target transient error (%s): %s; retry in %.2fs", target.selector.type, e, delay)
                            await sleep_seconds(delay)
                except Exception as e:
                    logger.exception("unexpected error on target: %s", e)
                    if span and Status and StatusCode:
                        span.set_status(Status(StatusCode.ERROR))
                    return ExecResult(target=target, errors=1, details=[f"unexpected:{e}"])

        sem = asyncio.Semaphore(self.concurrency)

        async def wrapped(tg: Target) -> ExecResult:
            async with sem:
                return await handle(tg)

        tasks = [wrapped(tg) for tg in targets]
        for coro in asyncio.as_completed(tasks):
            res = await coro
            # Structured audit log
            logger.info(
                "AUDIT %s",
                json.dumps(
                    {
                        "event": "soft_delete_result",
                        "task_id": task_id,
                        "selector": res.target.selector.type,
                        "processed": res.processed,
                        "skipped": res.skipped,
                        "errors": res.errors,
                        "time": iso_now(),
                        "dry_run": dry_run,
                    },
                    ensure_ascii=False,
                ),
            )
            results.append(res)

        finished = iso_now()
        summary = RunSummary(
            task_id=task_id,
            started_at=started,
            finished_at=finished,
            total_targets=len(results),
            processed_total=sum(r.processed for r in results),
            skipped_total=sum(r.skipped for r in results),
            errors_total=sum(r.errors for r in results),
            results=results,
        )
        return summary

# ---------- Example (documentation only) ----------

"""
Пример использования (упрощённо):

executor = SoftDeleteExecutor(concurrency=32)
summary = await executor.run(task_payload={
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "dry_run": False,
    "targets": [
        {
            "selector": {"type": "filesystem", "path_globs": ["var/log/app/*.log"]},
            "policy": {"safe_delete": True, "rate_limit_per_second": 1000}
        },
        {
            "selector": {"type": "s3", "bucket": "ov-prod-data", "path_globs": ["users/"]},
            "policy": {"safe_delete": True, "batch_size": 2000}
        },
        {
            "selector": {
                "type": "postgres",
                "uri": "postgresql://user:pass@db:5432/app",
                "schema": "app",
                "table": "users",
                "where_sql": "email = 'user@example.com'"
            },
            "policy": {"safe_delete": True, "batch_size": 5000, "rate_limit_per_second": 3000}
        }
    ]
})

Результат summary содержит агрегаты и детали по каждому таргету.
"""
