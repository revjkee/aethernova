from __future__ import annotations

import asyncio
import gzip
import io
import json
import logging
import os
import re
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Iterable, List, Literal, Mapping, Optional, Sequence, Tuple

# Optional external deps (graceful degradation)
try:
    from aiokafka import AIOKafkaProducer  # type: ignore
except Exception:  # pragma: no cover
    AIOKafkaProducer = None  # type: ignore

try:
    # project context (enrich logs, redis, settings)
    from cybersecurity.context import get_request_context, get_resources, get_settings  # type: ignore
except Exception:  # pragma: no cover
    def get_request_context():
        return None

    async def get_resources():  # type: ignore
        class _Dummy:
            redis = None
        return _Dummy()

    def get_settings():  # type: ignore
        class _S:
            ENV = "dev"
        return _S()

try:
    from pydantic import BaseModel, Field, ConfigDict
except Exception:  # pragma: no cover
    # Minimal fallback
    class BaseModel:  # type: ignore
        def __init__(self, **kwargs):  # pragma: no cover
            for k, v in kwargs.items():
                setattr(self, k, v)

    def Field(*args, **kwargs):  # type: ignore
        return None

    ConfigDict = dict  # type: ignore

# -----------------------------------------------------------------------------
# Logging with correlation enrichment
# -----------------------------------------------------------------------------

class _CtxFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        ctx = get_request_context()
        record.correlation_id = getattr(record, "correlation_id", None)
        record.tenant_id = getattr(record, "tenant_id", None)
        record.user_id = getattr(record, "user_id", None)
        if ctx:
            record.correlation_id = getattr(ctx, "correlation_id", None)
            record.tenant_id = str(getattr(ctx, "tenant_id", None)) if getattr(ctx, "tenant_id", None) else None
            record.user_id = str(getattr(ctx, "user_id", None)) if getattr(ctx, "user_id", None) else None
        return True

_logger = logging.getLogger(__name__)
if not _logger.handlers:
    _h = logging.StreamHandler(sys.stdout)
    _h.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s correlation_id=%(correlation_id)s tenant_id=%(tenant_id)s user_id=%(user_id)s"
    ))
    _h.addFilter(_CtxFilter())
    _logger.addHandler(_h)
_logger.setLevel(logging.INFO)

# -----------------------------------------------------------------------------
# Models / Results
# -----------------------------------------------------------------------------

class EventEnvelope(BaseModel):
    """Canonical event envelope for the Data Fabric."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    event_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    tenant_id: uuid.UUID
    type: str = Field(..., min_length=1, max_length=64, description="Logical event type, e.g. EDR_EVENT, IDS_ALERT")
    ts: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    body: Dict[str, Any] = Field(default_factory=dict)
    tags: Dict[str, str] = Field(default_factory=dict)
    schema_version: str = Field(default="v1")
    partition_key: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps({
            "event_id": str(self.event_id),
            "tenant_id": str(self.tenant_id),
            "type": self.type,
            "ts": self.ts.isoformat(),
            "body": self.body,
            "tags": self.tags,
            "schema_version": self.schema_version,
            "partition_key": self.partition_key,
        }, separators=(",", ":"), ensure_ascii=False)

@dataclass
class PublishResult:
    attempted: int
    succeeded: int
    failed: int
    errors: List[str] = field(default_factory=list)

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------

@dataclass
class DataFabricConfig:
    backend: Literal["localfs", "kafka"] = "localfs"

    # LocalFS
    fs_root: Path = Path(os.environ.get("DATAFABRIC_FS_ROOT", "datafabric"))
    fs_compress: bool = os.environ.get("DATAFABRIC_FS_COMPRESS", "1") == "1"
    fs_rotate_hours: int = int(os.environ.get("DATAFABRIC_FS_ROTATE_HOURS", "1"))
    fs_flush_max_lines: int = int(os.environ.get("DATAFABRIC_FS_FLUSH_MAX_LINES", "2000"))
    fs_dedup_ttl_sec: int = int(os.environ.get("DATAFABRIC_FS_DEDUP_TTL_SEC", "600"))

    # Kafka
    kafka_bootstrap: Optional[str] = os.environ.get("DATAFABRIC_KAFKA_BOOTSTRAP")
    kafka_client_id: str = os.environ.get("DATAFABRIC_KAFKA_CLIENT_ID", "cybersecurity-core")
    kafka_security_protocol: Optional[str] = os.environ.get("DATAFABRIC_KAFKA_SECURITY_PROTOCOL")  # PLAINTEXT/SASL_SSL
    kafka_sasl_mechanism: Optional[str] = os.environ.get("DATAFABRIC_KAFKA_SASL_MECHANISM")         # PLAIN/SCRAM-SHA-256/512
    kafka_sasl_user: Optional[str] = os.environ.get("DATAFABRIC_KAFKA_SASL_USER")
    kafka_sasl_pass: Optional[str] = os.environ.get("DATAFABRIC_KAFKA_SASL_PASS")
    kafka_topic_prefix: str = os.environ.get("DATAFABRIC_KAFKA_TOPIC_PREFIX", "soc.events")
    kafka_acks: str = os.environ.get("DATAFABRIC_KAFKA_ACKS", "all")
    kafka_compression_type: str = os.environ.get("DATAFABRIC_KAFKA_COMPRESSION", "gzip")
    kafka_batch_size: int = int(os.environ.get("DATAFABRIC_KAFKA_BATCH_SIZE", "32768"))
    kafka_linger_ms: int = int(os.environ.get("DATAFABRIC_KAFKA_LINGER_MS", "20"))
    kafka_max_in_flight: int = int(os.environ.get("DATAFABRIC_KAFKA_MAX_IN_FLIGHT", "5"))

    @staticmethod
    def from_env() -> "DataFabricConfig":
        backend = os.environ.get("DATAFABRIC_BACKEND", "localfs").lower()
        if backend not in ("localfs", "kafka"):
            backend = "localfs"
        return DataFabricConfig(backend=backend)

# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------

_SANITIZE_RE = re.compile(r"[^a-z0-9_\-]+")

def _sanitize_topic_fragment(value: str) -> str:
    v = value.strip().lower().replace(".", "_")
    v = _SANITIZE_RE.sub("_", v)
    return v[:48] or "unknown"

def _hour_bucket(ts: datetime) -> str:
    t = ts.astimezone(timezone.utc)
    return f"dt={t.strftime('%Y-%m-%d')}/hour={t.strftime('%H')}"

def _now() -> datetime:
    return datetime.now(timezone.utc)

# Simple async backoff with jitter
async def _retry_async(fn, *, retries=5, base_delay=0.05, max_delay=1.0, exc_types: Tuple[type, ...] = (Exception,)):
    attempt = 0
    while True:
        try:
            return await fn()
        except exc_types as e:
            attempt += 1
            if attempt > retries:
                raise
            delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
            delay = delay * (1.0 + (0.25 - os.urandom(1)[0] / 255.0 / 2.0))  # small jitter
            await asyncio.sleep(max(0.001, delay))

# -----------------------------------------------------------------------------
# Abstract adapter
# -----------------------------------------------------------------------------

class DataFabricAdapter:
    """Abstract Data Fabric adapter."""

    def __init__(self, config: DataFabricConfig) -> None:
        self.config = config

    async def start(self) -> None:  # pragma: no cover
        pass

    async def stop(self) -> None:  # pragma: no cover
        pass

    async def health(self) -> Dict[str, Any]:
        return {"ok": True, "backend": self.config.backend}

    async def publish(self, events: List[EventEnvelope]) -> PublishResult:
        raise NotImplementedError

    async def query(self, **kwargs) -> AsyncIterator[EventEnvelope]:  # pragma: no cover
        raise NotImplementedError

    async def store_blob(self, rel_path: str, data: bytes, *, content_type: str = "application/octet-stream") -> str:
        raise NotImplementedError

    async def get_blob(self, uri: str) -> bytes:
        raise NotImplementedError

# -----------------------------------------------------------------------------
# LocalFS implementation
# -----------------------------------------------------------------------------

class LocalFSAdapter(DataFabricAdapter):
    """
    Writes events as NDJSON.GZ, partitioned by tenant/type/hour.
    Provides simple query by path and blob store on FS.
    """

    def __init__(self, config: DataFabricConfig) -> None:
        super().__init__(config)
        self._root = Path(config.fs_root).resolve()
        self._locks: Dict[Path, asyncio.Lock] = {}
        self._dedup_local: Dict[str, float] = {}  # event_id -> expire_ts
        self._dedup_lock = asyncio.Lock()
        self._cleaner_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        self._root.mkdir(parents=True, exist_ok=True)
        self._cleaner_task = asyncio.create_task(self._dedup_cleaner())
        _logger.info("datafabric.localfs.started", extra={"root": str(self._root)})

    async def stop(self) -> None:
        if self._cleaner_task:
            self._cleaner_task.cancel()
            try:
                await self._cleaner_task
            except Exception:
                pass
        _logger.info("datafabric.localfs.stopped")

    async def health(self) -> Dict[str, Any]:
        ok = self._root.exists() and self._root.is_dir()
        return {"ok": ok, "backend": "localfs", "root": str(self._root)}

    def _file_for(self, ev: EventEnvelope) -> Path:
        tenant = str(ev.tenant_id)
        etype = _sanitize_topic_fragment(ev.type)
        bucket = _hour_bucket(ev.ts)
        dir_path = self._root / tenant / etype / bucket
        dir_path.mkdir(parents=True, exist_ok=True)
        fname = "events.ndjson.gz" if self.config.fs_compress else "events.ndjson"
        return dir_path / fname

    def _blob_path(self, rel_path: str) -> Path:
        p = self._root / "_blobs" / rel_path.lstrip("/").replace("..", "_")
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def _lock_for(self, path: Path) -> asyncio.Lock:
        lock = self._locks.get(path)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[path] = lock
        return lock

    async def _dedup_seen(self, event_id: uuid.UUID) -> bool:
        """
        Return True if already seen within TTL (using Redis if configured, otherwise in-memory).
        """
        key = f"df:dedup:{event_id}"
        ttl = self.config.fs_dedup_ttl_sec

        try:
            resources = await get_resources()
            if getattr(resources, "redis", None):
                # Use Redis SET with EX/NX
                rv = await resources.redis.set(key, "1", ex=ttl, nx=True)  # type: ignore[attr-defined]
                return rv is None  # if None, key existed -> seen
        except Exception:
            # fall back to local memory
            pass

        async with self._dedup_lock:
            now = time.time()
            # cleanup occasionally to keep map small
            self._dedup_local = {k: v for k, v in self._dedup_local.items() if v > now}
            if key in self._dedup_local:
                return True
            self._dedup_local[key] = now + ttl
            return False

    async def publish(self, events: List[EventEnvelope]) -> PublishResult:
        if not events:
            return PublishResult(attempted=0, succeeded=0, failed=0)

        attempted = len(events)
        succeeded = 0
        errors: List[str] = []

        # Group by destination file to minimize lock contention
        groups: Dict[Path, List[EventEnvelope]] = {}
        for ev in events:
            # Deduplicate by event_id within TTL
            try:
                if await self._dedup_seen(ev.event_id):
                    continue
            except Exception as e:
                _logger.warning("datafabric.localfs.dedup.error", extra={"err": str(e)})

            path = self._file_for(ev)
            groups.setdefault(path, []).append(ev)

        async def _write(path: Path, evs: List[EventEnvelope]) -> int:
            lock = self._lock_for(path)

            async def _do():
                # Append NDJSON or NDJSON.GZ
                if self.config.fs_compress:
                    # Concatenated gzip members are valid; open in 'ab' to append safely
                    with open(path, "ab") as raw:
                        with gzip.GzipFile(fileobj=raw, mode="ab") as gz:
                            for ev in evs:
                                line = (ev.to_json() + "\n").encode("utf-8")
                                gz.write(line)
                else:
                    with open(path, "ab") as f:
                        for ev in evs:
                            f.write((ev.to_json() + "\n").encode("utf-8"))
                return len(evs)

            async with lock:
                return await _retry_async(_do, retries=5, base_delay=0.05, max_delay=0.5)

        # Execute writes concurrently per file
        tasks = [asyncio.create_task(_write(p, evs)) for p, evs in groups.items()]
        for t in tasks:
            try:
                succeeded += await t
            except Exception as e:
                msg = str(e)
                _logger.error("datafabric.localfs.write.error", extra={"err": msg})
                errors.append(msg)

        failed = attempted - succeeded
        _logger.info("datafabric.localfs.publish", extra={"attempted": attempted, "succeeded": succeeded, "failed": failed})
        return PublishResult(attempted=attempted, succeeded=succeeded, failed=failed, errors=errors)

    async def query(
        self,
        tenant_id: uuid.UUID,
        type: str,
        since: datetime,
        until: Optional[datetime] = None,
    ) -> AsyncIterator[EventEnvelope]:
        """
        Iterate events from FS partitions. Simple sequential scan (dev/test usage).
        """
        etype = _sanitize_topic_fragment(type)
        base = self._root / str(tenant_id) / etype
        if not base.exists():
            return
        until = until or _now()
        cursor = since
        while cursor <= until:
            bucket = base / _hour_bucket(cursor)
            for fname in ("events.ndjson.gz", "events.ndjson"):
                file = bucket / fname
                if file.exists():
                    try:
                        if fname.endswith(".gz"):
                            with gzip.open(file, "rb") as f:
                                for raw in f:
                                    try:
                                        obj = json.loads(raw)
                                        yield EventEnvelope(
                                            event_id=uuid.UUID(obj["event_id"]),
                                            tenant_id=uuid.UUID(obj["tenant_id"]),
                                            type=obj["type"],
                                            ts=datetime.fromisoformat(obj["ts"]),
                                            body=obj.get("body") or {},
                                            tags=obj.get("tags") or {},
                                            schema_version=obj.get("schema_version", "v1"),
                                            partition_key=obj.get("partition_key"),
                                        )
                                    except Exception:
                                        continue
                        else:
                            with open(file, "rb") as f:
                                for raw in f:
                                    try:
                                        obj = json.loads(raw)
                                        yield EventEnvelope(
                                            event_id=uuid.UUID(obj["event_id"]),
                                            tenant_id=uuid.UUID(obj["tenant_id"]),
                                            type=obj["type"],
                                            ts=datetime.fromisoformat(obj["ts"]),
                                            body=obj.get("body") or {},
                                            tags=obj.get("tags") or {},
                                            schema_version=obj.get("schema_version", "v1"),
                                            partition_key=obj.get("partition_key"),
                                        )
                                    except Exception:
                                        continue
                    except Exception as e:
                        _logger.warning("datafabric.localfs.query.read_error", extra={"err": str(e), "file": str(file)})
            cursor = cursor + timedelta(hours=1)

    async def store_blob(self, rel_path: str, data: bytes, *, content_type: str = "application/octet-stream") -> str:
        path = self._blob_path(rel_path)
        path.write_bytes(data)
        return f"file://{path}"

    async def get_blob(self, uri: str) -> bytes:
        if not uri.startswith("file://"):
            raise ValueError("Only file:// URIs are supported by LocalFSAdapter.")
        path = Path(uri[len("file://"):])
        return path.read_bytes()

    async def _dedup_cleaner(self) -> None:
        while True:
            try:
                async with self._dedup_lock:
                    now = time.time()
                    self._dedup_local = {k: v for k, v in self._dedup_local.items() if v > now}
            except Exception:
                pass
            await asyncio.sleep(30)

# -----------------------------------------------------------------------------
# Kafka implementation (optional)
# -----------------------------------------------------------------------------

class KafkaAdapter(DataFabricAdapter):
    """
    Kafka adapter using aiokafka (optional).
    """

    def __init__(self, config: DataFabricConfig) -> None:
        super().__init__(config)
        self._producer: Optional[AIOKafkaProducer] = None

    def _build_topic(self, ev: EventEnvelope) -> str:
        # soc.events.{tenant}.{type}
        t = _sanitize_topic_fragment(str(ev.tenant_id))
        typ = _sanitize_topic_fragment(ev.type)
        return f"{self.config.kafka_topic_prefix}.{t}.{typ}"

    async def start(self) -> None:
        if AIOKafkaProducer is None:
            raise RuntimeError("aiokafka is not installed; Kafka backend unavailable.")
        kwargs: Dict[str, Any] = dict(
            bootstrap_servers=self.config.kafka_bootstrap,
            client_id=self.config.kafka_client_id,
            acks=self.config.kafka_acks,
            compression_type=self.config.kafka_compression_type,
            linger_ms=self.config.kafka_linger_ms,
            max_in_flight_requests_per_connection=self.config.kafka_max_in_flight,
            value_serializer=lambda v: v.encode("utf-8"),
            key_serializer=lambda v: v,  # bytes
        )
        # SASL
        if self.config.kafka_security_protocol:
            kwargs["security_protocol"] = self.config.kafka_security_protocol
        if self.config.kafka_sasl_mechanism:
            kwargs["sasl_mechanism"] = self.config.kafka_sasl_mechanism
        if self.config.kafka_sasl_user and self.config.kafka_sasl_pass:
            kwargs["sasl_plain_username"] = self.config.kafka_sasl_user
            kwargs["sasl_plain_password"] = self.config.kafka_sasl_pass

        self._producer = AIOKafkaProducer(**kwargs)  # type: ignore[arg-type]
        await self._producer.start()
        _logger.info("datafabric.kafka.started", extra={"bootstrap": self.config.kafka_bootstrap})

    async def stop(self) -> None:
        if self._producer:
            try:
                await self._producer.stop()
            except Exception:
                pass
            self._producer = None
        _logger.info("datafabric.kafka.stopped")

    async def health(self) -> Dict[str, Any]:
        ok = self._producer is not None
        return {"ok": ok, "backend": "kafka", "bootstrap": self.config.kafka_bootstrap}

    async def publish(self, events: List[EventEnvelope]) -> PublishResult:
        if not events:
            return PublishResult(attempted=0, succeeded=0, failed=0)
        if self._producer is None:
            raise RuntimeError("Kafka producer is not started.")

        attempted = len(events)
        succeeded = 0
        errors: List[str] = []

        async def _send(ev: EventEnvelope) -> None:
            topic = self._build_topic(ev)
            key = ev.event_id.bytes
            value = ev.to_json()
            await self._producer.send_and_wait(topic=topic, key=key, value=value)  # type: ignore[union-attr]

        send_tasks: List[asyncio.Task] = []
        for ev in events:
            task = asyncio.create_task(_retry_async(lambda ev=ev: _send(ev), retries=5, base_delay=0.02, max_delay=0.5))
            send_tasks.append(task)

        for t in send_tasks:
            try:
                await t
                succeeded += 1
            except Exception as e:
                msg = str(e)
                errors.append(msg)
                _logger.error("datafabric.kafka.send.error", extra={"err": msg})

        failed = attempted - succeeded
        _logger.info("datafabric.kafka.publish", extra={"attempted": attempted, "succeeded": succeeded, "failed": failed})
        return PublishResult(attempted=attempted, succeeded=succeeded, failed=failed, errors=errors)

    async def store_blob(self, rel_path: str, data: bytes, *, content_type: str = "application/octet-stream") -> str:
        # Kafka backend does not provide blob store; delegate to LocalFS under _blobs/
        fallback = LocalFSAdapter(self.config)
        await fallback.start()
        try:
            return await fallback.store_blob(rel_path, data, content_type=content_type)
        finally:
            await fallback.stop()

    async def get_blob(self, uri: str) -> bytes:
        fallback = LocalFSAdapter(self.config)
        await fallback.start()
        try:
            return await fallback.get_blob(uri)
        finally:
            await fallback.stop()

# -----------------------------------------------------------------------------
# Factory
# -----------------------------------------------------------------------------

def build_data_fabric_adapter(config: Optional[DataFabricConfig] = None) -> DataFabricAdapter:
    cfg = config or DataFabricConfig.from_env()
    if cfg.backend == "kafka":
        return KafkaAdapter(cfg)
    return LocalFSAdapter(cfg)

# -----------------------------------------------------------------------------
# __all__
# -----------------------------------------------------------------------------

__all__ = [
    "EventEnvelope",
    "PublishResult",
    "DataFabricConfig",
    "DataFabricAdapter",
    "LocalFSAdapter",
    "KafkaAdapter",
    "build_data_fabric_adapter",
]
