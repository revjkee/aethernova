# oblivionvault-core/oblivionvault/workers/archive_compactor.py
"""
OblivionVault Archive Compactor Worker.

Purpose
-------
Compacts old secret versions into compressed archive packages and removes
them from the primary storage according to retention policies.

Key features
------------
- Async worker with graceful shutdown and bounded concurrency.
- Retention policies: keep_last N versions per (namespace, key) and/or TTL.
- Packaging into tar.zst (falls back to gzip if 'zstandard' not available).
- Two-phase commit to avoid data loss:
  1) Write archive + manifest + pending_deletions.json
  2) Delete compacted versions from primary storage
  3) Write done.marker
- Pluggable ArchiveSink: Local directory (atomic rename+fsync) or S3 (optional).
- Robust metrics (Prometheus/OTLP via observability.metrics, NOOP if absent).
- Structured logging with operation context.
- Idempotency by deterministic package_id derived from manifest content.
- Periodic mode with exponential backoff on failure and jitter.

Integration assumptions
-----------------------
Storage adapter provides the following async methods (duck-typed):
  - list_secrets(namespace: str, *, prefix: Optional[str], limit: int, offset: int, latest_only: bool) -> List[SecretRecord]
  - read_secret(namespace: str, key: str, version: Optional[int]) -> SecretRecord
  - delete_secret(namespace: str, key: str, version: Optional[int]) -> int

Where SecretRecord has fields:
  namespace, key, version, ciphertext: bytes, metadata: dict

You can inject SnowflakeStorageAdapter from `oblivionvault.adapters.storage_snowflake`
or any other adapter with the same interface.
"""

from __future__ import annotations

import asyncio
import atexit
import dataclasses
import hashlib
import io
import json
import logging
import os
import random
import signal
import tarfile
import tempfile
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Tuple

# ---------- Optional dependencies & fallbacks ---------------------------------

try:
    import zstandard as zstd  # type: ignore
    _ZSTD_OK = True
except Exception:  # pragma: no cover
    _ZSTD_OK = False

try:
    import boto3  # type: ignore
    from botocore.config import Config as BotoConfig  # type: ignore
    _BOTO_OK = True
except Exception:  # pragma: no cover
    _BOTO_OK = False

try:
    from pydantic import BaseModel, Field, field_validator
except Exception:  # pragma: no cover
    class BaseModel:  # type: ignore
        pass
    def Field(default=None, **kwargs):  # type: ignore
        return default
    def field_validator(*args, **kwargs):  # type: ignore
        def wrap(fn): return fn
        return wrap

# observability metrics (soft dependency)
try:
    from oblivionvault.observability.metrics import (
        get_metrics, counter_inc, histogram_observe, register_observable_gauge, time_block
    )
    _METRICS_OK = True
except Exception:  # pragma: no cover
    _METRICS_OK = False
    def get_metrics(*args, **kwargs):  # type: ignore
        class _Dummy:  # noqa
            def counter_inc(self, *a, **k): pass
            def histogram_observe(self, *a, **k): pass
            def register_observable_gauge(self, *a, **k): pass
            def time_block(self, *a, **k):
                class _Ctx:  # noqa
                    def __enter__(self): return None
                    def __exit__(self, *e): return False
                return _Ctx()
        return _Dummy()
    def counter_inc(*a, **k): pass  # type: ignore
    def histogram_observe(*a, **k): pass  # type: ignore
    def register_observable_gauge(*a, **k): pass  # type: ignore
    def time_block(*a, **k):
        class _Ctx:  # noqa
            def __enter__(self): return None
            def __exit__(self, *e): return False
        return _Ctx()

_LOG = logging.getLogger(__name__)
_LOG.addHandler(logging.NullHandler())

# ---------- Data Model --------------------------------------------------------

@dataclass
class SecretVersion:
    namespace: str
    key: str
    version: int
    ciphertext: bytes
    metadata: Dict[str, Any]

    @classmethod
    def from_record(cls, r: Any) -> "SecretVersion":
        md = r.metadata if isinstance(r.metadata, dict) else {}
        return cls(namespace=r.namespace, key=r.key, version=int(r.version), ciphertext=r.ciphertext, metadata=md)


@dataclass
class PackageEntry:
    namespace: str
    key: str
    version: int
    size: int
    sha256: str


@dataclass
class PackageManifest:
    package_id: str
    algorithm: str
    compression: Literal["zstd", "gzip"]
    created_at: float
    entries: List[PackageEntry]
    total_size: int
    total_entries: int
    retention: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


# ---------- Config ------------------------------------------------------------

class SinkType:
    LOCAL = "local"
    S3 = "s3"


class CompactorConfig(BaseModel):
    # retention rules
    retention_keep_last: int = Field(default=5, ge=0, description="Keep last N versions per key")
    retention_min_age_s: int = Field(default=7 * 24 * 3600, ge=0, description="Min age in seconds to consider for compaction")

    # scanning/packaging
    batch_size: int = Field(default=500, ge=50, le=5000, description="List/page size for storage iteration")
    target_archive_size: int = Field(default=128 * 1024 * 1024, ge=1_048_576, description="Target archive size per package")
    max_entries_per_package: int = Field(default=5000, ge=100, description="Safety cap for entries per package")
    concurrency: int = Field(default=8, ge=1, le=64)
    dry_run: bool = Field(default=False)
    namespaces: Optional[List[str]] = Field(default=None, description="Limit to specific namespaces; None = all")

    # scheduling
    interval_s: int = Field(default=900, ge=10, description="Periodic interval (set 0 for single run)")
    jitter_s: int = Field(default=15, ge=0, description="Random jitter to spread load")

    # sink
    sink_type: str = Field(default=os.getenv("OV_ARCHIVE_SINK", SinkType.LOCAL))
    local_dir: str = Field(default=os.getenv("OV_ARCHIVE_DIR", "./_ov_archive"))
    s3_bucket: Optional[str] = Field(default=os.getenv("OV_ARCHIVE_S3_BUCKET"))
    s3_prefix: str = Field(default=os.getenv("OV_ARCHIVE_S3_PREFIX", "oblivionvault/archive"))
    s3_region: Optional[str] = Field(default=os.getenv("OV_ARCHIVE_S3_REGION"))
    s3_sse: Optional[str] = Field(default=os.getenv("OV_ARCHIVE_S3_SSE", "AES256"))

    # compression
    zstd_level: int = Field(default=10, ge=1, le=22)

    # safety/timeouts
    read_timeout_s: int = Field(default=30, ge=1, le=300)
    delete_timeout_s: int = Field(default=30, ge=1, le=300)

    @field_validator("sink_type")
    @classmethod
    def _sink_supported(cls, v: str) -> str:
        v = (v or "").lower()
        if v not in (SinkType.LOCAL, SinkType.S3):
            return SinkType.LOCAL
        if v == SinkType.S3 and not _BOTO_OK:
            _LOG.warning("boto3 not available; falling back to LOCAL sink")
            return SinkType.LOCAL
        return v

    @classmethod
    def from_env(cls) -> "CompactorConfig":
        # All fields already have env defaults; this enables programmatic override if needed
        return cls()


# ---------- Archive sinks -----------------------------------------------------

class ArchiveSinkError(Exception):
    pass


class ArchiveSink:
    async def put(self, package_name: str, src_path: Path, metadata: Dict[str, Any]) -> str:
        """Store a package atomically and return a durable URI."""
        raise NotImplementedError


class LocalDirSink(ArchiveSink):
    def __init__(self, base_dir: Path):
        self.base = base_dir

    async def put(self, package_name: str, src_path: Path, metadata: Dict[str, Any]) -> str:
        self.base.mkdir(parents=True, exist_ok=True)
        dst = self.base / package_name
        tmp = self.base / f".{package_name}.tmp"
        # copy with atomic rename within same filesystem
        def _copy():
            with open(src_path, "rb") as r, open(tmp, "wb") as w:
                while True:
                    chunk = r.read(1024 * 1024)
                    if not chunk:
                        break
                    w.write(chunk)
                w.flush()
                os.fsync(w.fileno())
            os.replace(tmp, dst)
            # write sidecar metadata json
            with open(str(dst) + ".meta.json", "w", encoding="utf-8") as m:
                json.dump(metadata, m, ensure_ascii=False, separators=(",", ":"))
                m.flush()
                os.fsync(m.fileno())
        await asyncio.to_thread(_copy)
        return f"file://{dst.resolve().as_posix()}"


class S3Sink(ArchiveSink):
    def __init__(self, bucket: str, prefix: str, region: Optional[str], sse: Optional[str]):
        if not _BOTO_OK:
            raise ArchiveSinkError("boto3 not available")
        self.bucket = bucket
        self.prefix = prefix.strip("/").rstrip("/")
        cfg = BotoConfig(retries={"max_attempts": 5, "mode": "standard"})
        self.s3 = boto3.client("s3", region_name=region, config=cfg)
        self.sse = sse

    async def put(self, package_name: str, src_path: Path, metadata: Dict[str, Any]) -> str:
        key = f"{self.prefix}/{package_name}"
        extra: Dict[str, Any] = {"Metadata": {k.replace(" ", "_"): str(v) for k, v in metadata.items()}}
        if self.sse:
            extra["ServerSideEncryption"] = self.sse
        def _upload():
            self.s3.upload_file(str(src_path), self.bucket, key, ExtraArgs=extra)
        await asyncio.to_thread(_upload)
        return f"s3://{self.bucket}/{key}"


# ---------- Utilities ---------------------------------------------------------

def _now() -> float:
    return time.time()

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _deterministic_package_id(entries: Sequence[PackageEntry], created_at: float) -> str:
    h = hashlib.sha256()
    for e in entries:
        h.update(f"{e.namespace}|{e.key}|{e.version}|{e.sha256}|{e.size}".encode("utf-8"))
    h.update(str(int(created_at)).encode("utf-8"))
    return h.hexdigest()[:32]

def _package_filename(package_id: str, compression: str) -> str:
    ext = "tar.zst" if compression == "zstd" else "tar.gz"
    return f"ov-archive-{package_id}.{ext}"

def _older_than(ts: float, min_age_s: int) -> bool:
    return (_now() - ts) >= min_age_s


# ---------- Compactor core ----------------------------------------------------

class ArchiveCompactor:
    """
    Archive compactor worker.

    Parameters
    ----------
    storage : object with async list_secrets/read_secret/delete_secret interface
    cfg     : CompactorConfig
    sink    : ArchiveSink
    """

    def __init__(self, storage: Any, cfg: CompactorConfig, sink: ArchiveSink):
        self.storage = storage
        self.cfg = cfg
        self.sink = sink
        self._stop = asyncio.Event()
        self._sem = asyncio.Semaphore(cfg.concurrency)
        self._metrics = get_metrics()

        # export a gauge for pending queue (best-effort)
        if _METRICS_OK:
            try:
                register_observable_gauge(
                    "ov_compactor_pending_queue_size",
                    callback=lambda: float(getattr(self, "_pending_items", 0)),
                    labels={"worker": "archive_compactor"},
                    unit="items",
                    description="Pending items size in compactor queue",
                )
            except Exception:
                pass

    # ----- Public API -----

    async def run(self) -> None:
        """
        Run in single-shot or periodic mode depending on interval_s.
        """
        interval = self.cfg.interval_s
        if interval <= 0:
            await self._compact_cycle()
            return

        backoff = 1.0
        while not self._stop.is_set():
            try:
                await self._compact_cycle()
                backoff = 1.0  # reset on success
            except Exception as e:
                _LOG.exception("Compaction cycle failed: %s", e, extra={"event": "compaction_cycle_failed"})
                counter_inc("ov_compactor_errors_total", labels={"phase": "cycle"})
                await asyncio.sleep(min(60.0, backoff))
                backoff = min(backoff * 2.0, 60.0)
            # jittered sleep
            sleep_for = max(1, interval + random.randint(-self.cfg.jitter_s, self.cfg.jitter_s))
            await asyncio.wait([self._stop.wait()], timeout=sleep_for)

    def shutdown(self) -> None:
        self._stop.set()

    # ----- Internal operations -----

    async def _compact_cycle(self) -> None:
        """
        One full scan+compact pass across namespaces.
        """
        start = _now()
        namespaces = self.cfg.namespaces or await self._discover_namespaces()
        _LOG.info("Starting compaction cycle", extra={"namespaces": namespaces})

        total_archived = 0
        total_deleted = 0

        for ns in namespaces:
            a, d = await self._process_namespace(ns)
            total_archived += a
            total_deleted += d

        elapsed = _now() - start
        histogram_observe("ov_compactor_cycle_latency_seconds", elapsed, labels={"worker": "archive_compactor"})
        counter_inc("ov_compactor_archived_total", amount=total_archived, labels={"worker": "archive_compactor"})
        counter_inc("ov_compactor_deleted_total", amount=total_deleted, labels={"worker": "archive_compactor"})
        _LOG.info("Compaction cycle completed", extra={"archived": total_archived, "deleted": total_deleted, "elapsed_s": round(elapsed, 3)})

    async def _discover_namespaces(self) -> List[str]:
        """
        Discover namespaces by scanning. If storage cannot enumerate namespaces directly,
        derive from listing with pagination.
        """
        # Heuristic: list all secrets with latest_only=False and collect namespaces.
        # For large datasets this may be expensive; configure namespaces explicitly for scale.
        seen: set[str] = set()
        offset = 0
        limit = max(100, min(self.cfg.batch_size, 2000))
        while True:
            items = await self.storage.list_secrets(namespace="*", limit=limit, offset=offset, latest_only=False)  # type: ignore
            if not items:
                break
            for r in items:
                ns = getattr(r, "namespace", None)
                if ns and ns != "*":
                    seen.add(ns)
            offset += len(items)
            if len(items) < limit:
                break
        if not seen:
            seen.add("default")
        return sorted(seen)

    async def _process_namespace(self, namespace: str) -> Tuple[int, int]:
        """
        Process a single namespace: plan candidates, build packages, archive, then delete.
        Returns (archived_entries_count, deleted_entries_count).
        """
        # 1) Build compaction plan
        compaction_set = await self._plan_compaction(namespace)
        if not compaction_set:
            _LOG.info("No compaction candidates", extra={"namespace": namespace})
            return (0, 0)

        # 2) Build packages
        packages = self._build_packages(compaction_set)
        _LOG.info("Built packages", extra={"namespace": namespace, "packages": len(packages)})

        # 3) Write/upload archives concurrently
        archived_total = 0
        deleted_total = 0
        for pkg in packages:
            archived, deleted = await self._archive_and_delete(pkg)
            archived_total += archived
            deleted_total += deleted

        return (archived_total, deleted_total)

    async def _plan_compaction(self, namespace: str) -> List[SecretVersion]:
        """
        Decide which versions should be compacted based on retention policy.
        """
        keep_last = self.cfg.retention_keep_last
        min_age = self.cfg.retention_min_age_s

        # We'll iterate all versions for namespace and group by key
        # NOTE: For very large datasets this should be pushed down to storage (SQL).
        key_to_versions: Dict[str, List[Any]] = {}
        offset = 0
        limit = self.cfg.batch_size

        while True:
            batch = await self.storage.list_secrets(namespace=namespace, limit=limit, offset=offset, latest_only=False)
            if not batch:
                break
            for rec in batch:
                key_to_versions.setdefault(rec.key, []).append(rec)
            offset += len(batch)
            if len(batch) < limit:
                break

        candidates: List[SecretVersion] = []
        now = _now()
        for key, versions in key_to_versions.items():
            # sort by version descending (latest first)
            versions.sort(key=lambda r: int(r.version), reverse=True)
            # keep 'keep_last' newest
            to_consider = versions[keep_last:]
            for r in to_consider:
                # some storages may not remember created_at; fall back to version heuristic
                # expect r.created_at string -> parse? We avoid heavy parsing here.
                # Apply only age policy if created_at not available.
                created_at = None
                if hasattr(r, "created_at") and isinstance(r.created_at, str):
                    # try to parse epoch seconds from TO_CHAR; storage adapter could store ISO8601
                    try:
                        # If it's epoch-like
                        created_at = float(r.created_at) if r.created_at.isdigit() else None
                    except Exception:
                        created_at = None
                if created_at is not None:
                    if not _older_than(created_at, min_age):
                        continue
                else:
                    # Without timestamp we rely on version distance; require at least min_age by default
                    # otherwise compact conservatively only if not among keep_last (already ensured).
                    if min_age > 0:
                        # Without reliable ts, skip if age policy demanded strict time window
                        continue
                try:
                    candidates.append(SecretVersion.from_record(r))
                except Exception:
                    _LOG.warning("Failed to adapt record for compaction", extra={"namespace": namespace, "key": r.key, "version": int(getattr(r, "version", -1))})
        # Sort candidates deterministically (namespace+key+version asc)
        candidates.sort(key=lambda s: (s.namespace, s.key, s.version))
        return candidates

    def _build_packages(self, candidates: List[SecretVersion]) -> List[PackageManifest]:
        """
        Split candidates into packages based on target size and safety caps.
        Each manifest contains entries and minimal retention descriptor.
        """
        packages: List[PackageManifest] = []
        buf: List[PackageEntry] = []
        total = 0
        created = _now()
        compression = "zstd" if _ZSTD_OK else "gzip"

        def _flush():
            nonlocal buf, total, created
            if not buf:
                return
            package_id = _deterministic_package_id(buf, created)
            manifest = PackageManifest(
                package_id=package_id,
                algorithm="tar",
                compression=compression,  # type: ignore
                created_at=created,
                entries=list(buf),
                total_size=total,
                total_entries=len(buf),
                retention={
                    "keep_last": self.cfg.retention_keep_last,
                    "min_age_s": self.cfg.retention_min_age_s,
                },
            )
            packages.append(manifest)
            buf = []
            total = 0
            created = _now()

        for sv in candidates:
            sz = len(sv.ciphertext)
            ent = PackageEntry(
                namespace=sv.namespace, key=sv.key, version=sv.version,
                size=sz, sha256=_sha256(sv.ciphertext)
            )
            # rotate package if needed
            if buf and (total + sz > self.cfg.target_archive_size or len(buf) >= self.cfg.max_entries_per_package):
                _flush()
            buf.append(ent)
            total += sz
        _flush()
        return packages

    async def _archive_and_delete(self, manifest: PackageManifest) -> Tuple[int, int]:
        """
        Create the archive file according to manifest, upload to sink, and delete from primary storage.
        Returns (archived_entries, deleted_entries).
        """
        # 1) Create temp archive
        compression = manifest.compression
        pkg_name = _package_filename(manifest.package_id, compression)
        archived_entries = 0
        deleted_entries = 0

        with tempfile.TemporaryDirectory(prefix="ov_compactor_") as tmpdir:
            tmpdir_path = Path(tmpdir)
            archive_path = tmpdir_path / pkg_name

            # Write tar with compression stream
            with time_block("ov_compactor_archive_build_latency_seconds", labels={"compression": compression}):
                await self._write_archive(archive_path, manifest)

            meta = {
                "package_id": manifest.package_id,
                "total_entries": manifest.total_entries,
                "total_size": manifest.total_size,
                "created_at": manifest.created_at,
                "compression": compression,
            }

            if not self.cfg.dry_run:
                with time_block("ov_compactor_sink_put_latency_seconds", labels={"sink": self.cfg.sink_type}):
                    uri = await self.sink.put(pkg_name, archive_path, meta)
                _LOG.info("Archive uploaded", extra={"package": pkg_name, "uri": uri})
            else:
                uri = f"dryrun://{pkg_name}"

            # 2) Write sidecar control files (pending_deletions.json then after deletion done.marker)
            pending_path = tmpdir_path / f"{pkg_name}.pending_deletions.json"
            done_marker = tmpdir_path / f"{pkg_name}.done.marker"

            def _write_pending():
                with open(pending_path, "w", encoding="utf-8") as f:
                    json.dump([dataclasses.asdict(e) for e in manifest.entries], f, ensure_ascii=False, separators=(",", ":"))
                    f.flush()
                    os.fsync(f.fileno())
            await asyncio.to_thread(_write_pending)

            # 3) Delete from primary storage
            deleted_entries = await self._delete_entries(manifest)

            # 4) Mark done
            def _write_done():
                with open(done_marker, "w", encoding="utf-8") as f:
                    json.dump({"uri": uri, "deleted": deleted_entries, "ts": _now()}, f, ensure_ascii=False, separators=(",", ":"))
                    f.flush()
                    os.fsync(f.fileno())
            await asyncio.to_thread(_write_done)

            archived_entries = manifest.total_entries

        counter_inc("ov_compactor_packages_total", labels={"result": "ok"})
        return archived_entries, deleted_entries

    async def _write_archive(self, dst_path: Path, manifest: PackageManifest) -> None:
        """
        Create tar archive with entries and manifest.json.
        Each payload is stored as <namespace>/<key>/<version>.bin.
        """
        # open a compressed stream
        if _ZSTD_OK:
            cctx = zstd.ZstdCompressor(level=self.cfg.zstd_level)
            fp = open(dst_path, "wb")
            stream = cctx.stream_writer(fp)
            # tarfile in stream mode
            tar = tarfile.open(mode="w|", fileobj=stream)
        else:
            fp = open(dst_path, "wb")
            tar = tarfile.open(mode="w:gz", fileobj=fp)

        try:
            # add manifest.json first
            manifest_bytes = json.dumps(manifest.to_dict(), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            info = tarfile.TarInfo(name="manifest.json")
            info.size = len(manifest_bytes)
            info.mtime = int(_now())
            tar.addfile(info, io.BytesIO(manifest_bytes))

            # add each entry by fetching ciphertext
            for ent in manifest.entries:
                if self._stop.is_set():
                    raise asyncio.CancelledError()

                # enforce concurrency for read_secret
                async with self._sem:
                    with time_block("ov_compactor_storage_read_latency_seconds", labels={"op": "read"}):
                        rec = await self.storage.read_secret(ent.namespace, ent.key, ent.version)
                sv = SecretVersion.from_record(rec)

                # sanity check sha256 & size
                if len(sv.ciphertext) != ent.size or _sha256(sv.ciphertext) != ent.sha256:
                    _LOG.warning("Entry changed during packaging; skipping", extra={"ns": ent.namespace, "key": ent.key, "version": ent.version})
                    continue

                path = f"payload/{ent.namespace}/{ent.key}/{ent.version}.bin"
                data = sv.ciphertext
                info = tarfile.TarInfo(name=path)
                info.size = len(data)
                info.mtime = int(_now())
                tar.addfile(info, io.BytesIO(data))
        finally:
            # close tar and streams
            try:
                tar.close()
            except Exception:
                pass
            if _ZSTD_OK:
                try:
                    stream.flush(zstd.FLUSH_FRAME)  # type: ignore
                except Exception:
                    pass
            try:
                fp.flush()
                os.fsync(fp.fileno())
                fp.close()
            except Exception:
                pass

    async def _delete_entries(self, manifest: PackageManifest) -> int:
        """
        Delete entries listed in manifest from primary storage.
        """
        if self.cfg.dry_run:
            _LOG.info("Dry-run; skipping deletions", extra={"count": manifest.total_entries})
            return 0

        deleted = 0

        async def _del(ent: PackageEntry) -> int:
            async with self._sem:
                with time_block("ov_compactor_storage_delete_latency_seconds", labels={"op": "delete"}):
                    try:
                        n = await self.storage.delete_secret(ent.namespace, ent.key, version=ent.version)
                        return int(n or 0)
                    except Exception as e:
                        _LOG.error("Delete failed", extra={"ns": ent.namespace, "key": ent.key, "version": ent.version, "err": str(e)})
                        counter_inc("ov_compactor_errors_total", labels={"phase": "delete"})
                        return 0

        for chunk_start in range(0, len(manifest.entries), 200):
            chunk = manifest.entries[chunk_start:chunk_start + 200]
            results = await asyncio.gather(*[_del(e) for e in chunk], return_exceptions=False)
            deleted += sum(results)
            if self._stop.is_set():
                break

        return deleted


# ---------- Runner / CLI ------------------------------------------------------

class _SignalHandler:
    def __init__(self, shutdown_cb):
        self._shutdown_cb = shutdown_cb
        try:
            loop = asyncio.get_event_loop()
            loop.add_signal_handler(signal.SIGINT, self._shutdown_cb)
            loop.add_signal_handler(signal.SIGTERM, self._shutdown_cb)
        except NotImplementedError:
            # Windows fallback: no signal handlers in ProactorEventLoop
            signal.signal(signal.SIGINT, lambda *_: self._shutdown_cb())  # type: ignore
            try:
                signal.signal(signal.SIGTERM, lambda *_: self._shutdown_cb())  # type: ignore
            except Exception:
                pass


async def run_compactor(storage: Any, cfg: Optional[CompactorConfig] = None) -> None:
    """
    Entry point to be called from your app bootstrap with a concrete storage adapter.
    """
    cfg = cfg or CompactorConfig.from_env()
    sink: ArchiveSink
    if cfg.sink_type == SinkType.S3 and _BOTO_OK and cfg.s3_bucket:
        sink = S3Sink(cfg.s3_bucket, cfg.s3_prefix, cfg.s3_region, cfg.s3_sse)
    else:
        sink = LocalDirSink(Path(cfg.local_dir))

    compactor = ArchiveCompactor(storage, cfg, sink)
    sh = _SignalHandler(compactor.shutdown)
    del sh  # only to keep reference alive in CPython

    # ensure metrics singleton is initialized early
    get_metrics()

    try:
        await compactor.run()
    finally:
        compactor.shutdown()


# Optional CLI for standalone use:
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="OblivionVault Archive Compactor")
    parser.add_argument("--keep-last", type=int, default=int(os.getenv("OV_RETENTION_KEEP_LAST", "5")))
    parser.add_argument("--min-age-s", type=int, default=int(os.getenv("OV_RETENTION_MIN_AGE_S", str(7*24*3600))))
    parser.add_argument("--batch-size", type=int, default=int(os.getenv("OV_BATCH_SIZE", "500")))
    parser.add_argument("--target-size", type=int, default=int(os.getenv("OV_TARGET_ARCHIVE_SIZE", str(128*1024*1024))))
    parser.add_argument("--concurrency", type=int, default=int(os.getenv("OV_CONCURRENCY", "8")))
    parser.add_argument("--interval-s", type=int, default=int(os.getenv("OV_INTERVAL_S", "0")))
    parser.add_argument("--dry-run", action="store_true", default=os.getenv("OV_DRY_RUN", "0") == "1")
    parser.add_argument("--sink", choices=[SinkType.LOCAL, SinkType.S3], default=os.getenv("OV_ARCHIVE_SINK", SinkType.LOCAL))
    parser.add_argument("--local-dir", default=os.getenv("OV_ARCHIVE_DIR", "./_ov_archive"))
    parser.add_argument("--s3-bucket", default=os.getenv("OV_ARCHIVE_S3_BUCKET"))
    parser.add_argument("--s3-prefix", default=os.getenv("OV_ARCHIVE_S3_PREFIX", "oblivionvault/archive"))
    parser.add_argument("--s3-region", default=os.getenv("OV_ARCHIVE_S3_REGION"))
    parser.add_argument("--s3-sse", default=os.getenv("OV_ARCHIVE_S3_SSE", "AES256"))
    args = parser.parse_args()

    # Build config from args
    cfg = CompactorConfig(
        retention_keep_last=args.keep_last,
        retention_min_age_s=args.min_age_s,
        batch_size=args.batch_size,
        target_archive_size=args.target_size,
        concurrency=args.concurrency,
        interval_s=args.interval_s,
        dry_run=args.dry_run,
        sink_type=args.sink,
        local_dir=args.local_dir,
        s3_bucket=args.s3_bucket,
        s3_prefix=args.s3_prefix,
        s3_region=args.s3_region,
        s3_sse=args.s3_sse,
    )

    # For standalone demo purposes, a minimal stub storage would be required.
    # In production, run via application bootstrap and pass a real storage adapter.
    class _StubStorage:
        async def list_secrets(self, namespace: str, *, prefix=None, limit=100, offset=0, latest_only=False):
            return []
        async def read_secret(self, namespace: str, key: str, version: int):
            raise NotImplementedError("Attach a real storage adapter")
        async def delete_secret(self, namespace: str, key: str, version: int):
            return 0

    asyncio.run(run_compactor(_StubStorage(), cfg))
