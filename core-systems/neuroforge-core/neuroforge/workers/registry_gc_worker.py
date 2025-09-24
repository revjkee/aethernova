# neuroforge-core/neuroforge/workers/registry_gc_worker.py
"""
NeuroForge Registry GC Worker (industrial-grade)

Назначение:
  Асинхронный сборщик мусора реестра артефактов/блобов:
   - Находит и удаляет сиротские блобы (ref_count=0, возраст > min_blob_age)
   - Чистит просроченные артефакты (unpinned, старше retention), не имеющие актуальных ссылок
   - Удаляет незавершённые загрузки (stale uploads) по TTL
   - Обновляет БД (soft-delete), удаляет объекты в S3
   - Работает в единственном экземпляре за счёт распределённого lock в Redis
   - Метрики Prometheus и health эндпойнт на одном HTTP-порте

Зависимости (минимум):
  - python >= 3.10
  - pydantic-settings (или pydantic>=1 BaseSettings)
  - sqlalchemy[asyncio]
  - redis>=5 (redis.asyncio)
  - aioboto3
  - aiohttp
  - prometheus_client
  - structlog (опционально; при отсутствии – fallback на logging)

Ожидаемая БД-схема (упрощённо, адаптируйте под свой проект):
  blobs(id UUID PK, key TEXT UNIQUE, size_bytes BIGINT, ref_count INT, created_at TIMESTAMPTZ,
        deleted_at TIMESTAMPTZ NULL)
  artifacts(id UUID PK, pinned BOOL, updated_at TIMESTAMPTZ, deleted_at TIMESTAMPTZ NULL)
  artifact_blobs(artifact_id UUID FK, blob_id UUID FK) -- связи артефакт↔блоб
  uploads(id UUID PK, key TEXT, created_at TIMESTAMPTZ, finalized BOOL DEFAULT FALSE)

Принципы безопасности:
  - Сначала удаление в объектном хранилище, затем soft-delete в БД
  - Проверки ref_count и deleted_at при апдейте
  - Все выборки — с ограничением по batch_size
  - Dry-run для безопасной проверки

Автор: NeuroForge Core
Лицензия: Internal / Proprietary (адаптируйте при необходимости)
"""
from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import socket
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple
from uuid import uuid4

# ---- Logging (structlog -> fallback to logging) --------------------------------
try:
    import structlog

    def _configure_logging() -> Any:
        structlog.configure(
            processors=[
                structlog.processors.TimeStamper(fmt="iso", utc=True),
                structlog.processors.add_log_level,
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.dev.ConsoleRenderer() if os.getenv("DEV_LOG", "0") == "1"
                else structlog.processors.JSONRenderer(),
            ],
            wrapper_class=structlog.make_filtering_bound_logger(
                level="INFO" if os.getenv("LOG_LEVEL", "INFO") == "INFO" else "DEBUG"
            ),
        )
        return structlog.get_logger()
    log = _configure_logging()
except Exception:
    import logging

    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    log = logging.getLogger("registry-gc")

# ---- Settings ------------------------------------------------------------------
try:
    from pydantic_settings import BaseSettings
except Exception:  # pydantic<2 fallback
    from pydantic import BaseSettings  # type: ignore

from pydantic import Field

class Settings(BaseSettings):
    # Identity
    app_name: str = Field(default="neuroforge.registry.gc")

    # DB / Redis / S3
    db_dsn: str = Field(..., description="Async SQLAlchemy DSN, e.g. postgresql+asyncpg://user:pass@host/db")
    redis_url: str = Field(..., description="redis://host:port/0")
    s3_bucket: str = Field(..., description="Target bucket")
    s3_endpoint_url: Optional[str] = None
    s3_access_key: Optional[str] = None
    s3_secret_key: Optional[str] = None
    s3_region: Optional[str] = None
    s3_use_ssl: bool = True
    s3_key_prefix: str = Field(default="", description="Prefix in bucket for registry blobs")

    # GC algorithm
    loop_interval_seconds: int = 120
    batch_size: int = 200
    concurrency: int = 8
    min_blob_age_hours: int = 24
    artifact_retention_days: int = 30
    uploads_ttl_hours: int = 6
    dry_run: bool = False

    # Lock
    lock_ttl_seconds: int = 600
    lock_name: str = "neuroforge:registry_gc:lock"

    # HTTP (health/metrics)
    http_host: str = "0.0.0.0"
    http_port: int = 9753

    class Config:
        env_prefix = "NEUROFORGE_"
        case_sensitive = False

# ---- Metrics -------------------------------------------------------------------
from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry, CONTENT_TYPE_LATEST, generate_latest
from aiohttp import web

REGISTRY = CollectorRegistry()

MET_GC_RUNS = Counter("nf_gc_runs_total", "GC runs", registry=REGISTRY)
MET_GC_BLOBS_DELETED = Counter("nf_gc_blobs_deleted_total", "Deleted blobs count", registry=REGISTRY)
MET_GC_ARTIFACTS_DELETED = Counter("nf_gc_artifacts_deleted_total", "Deleted artifacts count", registry=REGISTRY)
MET_GC_UPLOADS_DELETED = Counter("nf_gc_uploads_deleted_total", "Deleted stale uploads count", registry=REGISTRY)
MET_GC_BYTES_FREED = Counter("nf_gc_bytes_freed_total", "Total bytes freed", registry=REGISTRY)
MET_GC_ERRORS = Counter("nf_gc_errors_total", "Total errors during GC", registry=REGISTRY)
MET_GC_DURATION = Histogram("nf_gc_run_duration_seconds", "GC run duration seconds", registry=REGISTRY, buckets=(0.1, 0.5, 1, 2, 5, 10, 20, 60, 120, 300))
G_READY = Gauge("nf_gc_ready", "1 if worker ready", registry=REGISTRY)
G_LOCK_HELD = Gauge("nf_gc_lock_held", "1 if lock held", registry=REGISTRY)

# ---- Storage & DB clients ------------------------------------------------------
from sqlalchemy.ext.asyncio import create_async_engine, AsyncEngine, AsyncConnection
from sqlalchemy import text

import aioboto3
import redis.asyncio as aioredis

# ---- Helpers -------------------------------------------------------------------
def utcnow() -> datetime:
    return datetime.now(timezone.utc)

async def async_backoff(fn, *args, max_attempts=5, base_delay=0.25, exc_types=(Exception,), **kwargs):
    attempt = 0
    while True:
        try:
            return await fn(*args, **kwargs)
        except exc_types as e:
            attempt += 1
            if attempt >= max_attempts:
                raise
            delay = base_delay * (2 ** (attempt - 1))
            await asyncio.sleep(delay)

@dataclass
class BlobCandidate:
    id: str
    key: str
    size_bytes: int

@dataclass
class ArtifactCandidate:
    id: str

@dataclass
class UploadCandidate:
    id: str
    key: str

# ---- GC Worker -----------------------------------------------------------------
class RegistryGCWorker:
    def __init__(self, settings: Settings):
        self.s = settings
        self._shutdown = asyncio.Event()
        self._lock_value = f"{socket.gethostname()}:{os.getpid()}:{uuid4()}"
        self._lock_held = False

        self.db_engine: AsyncEngine = create_async_engine(self.s.db_dsn, pool_pre_ping=True, pool_size=5, max_overflow=5, future=True)
        self.redis = aioredis.from_url(self.s.redis_url, encoding="utf-8", decode_responses=True)
        self.s3_session = aioboto3.Session()

        self._http_app = web.Application()
        self._http_app.add_routes([
            web.get("/healthz", self._handle_health),
            web.get("/metrics", self._handle_metrics),
        ])
        self._http_runner: Optional[web.AppRunner] = None
        self._http_site: Optional[web.TCPSite] = None

        self._sem = asyncio.Semaphore(self.s.concurrency)

    # ---------------- HTTP ----------------
    async def _handle_health(self, request: web.Request) -> web.Response:
        status = {
            "name": self.s.app_name,
            "time": utcnow().isoformat(),
            "lock_held": self._lock_held,
            "ready": True,
            "dry_run": self.s.dry_run,
        }
        return web.json_response(status)

    async def _handle_metrics(self, request: web.Request) -> web.Response:
        data = generate_latest(REGISTRY)
        return web.Response(body=data, headers={"Content-Type": CONTENT_TYPE_LATEST})

    async def start_http(self):
        self._http_runner = web.AppRunner(self._http_app)
        await self._http_runner.setup()
        self._http_site = web.TCPSite(self._http_runner, host=self.s.http_host, port=self.s.http_port)
        await self._http_site.start()
        G_READY.set(1.0)
        log.info("http_server_started", host=self.s.http_host, port=self.s.http_port)

    async def stop_http(self):
        G_READY.set(0.0)
        with contextlib.suppress(Exception):
            if self._http_site:
                await self._http_site.stop()
            if self._http_runner:
                await self._http_runner.cleanup()

    # --------------- Locking ---------------
    async def acquire_lock(self) -> bool:
        try:
            ok = await self.redis.set(self.s.lock_name, self._lock_value, ex=self.s.lock_ttl_seconds, nx=True)
            self._lock_held = bool(ok)
            G_LOCK_HELD.set(1.0 if ok else 0.0)
            return bool(ok)
        except Exception as e:
            MET_GC_ERRORS.inc()
            log.error("lock_acquire_error", error=str(e))
            return False

    async def refresh_lock(self) -> None:
        if not self._lock_held:
            return
        # Extend TTL if we still own the lock (atomic Lua)
        script = """
        if redis.call("get", KEYS[1]) == ARGV[1] then
            return redis.call("expire", KEYS[1], ARGV[2])
        else
            return 0
        end
        """
        try:
            await self.redis.eval(script, 1, self.s.lock_name, self._lock_value, str(self.s.lock_ttl_seconds))
        except Exception as e:
            MET_GC_ERRORS.inc()
            log.error("lock_refresh_error", error=str(e))
            self._lock_held = False
            G_LOCK_HELD.set(0.0)

    async def release_lock(self) -> None:
        if not self._lock_held:
            return
        script = """
        if redis.call("get", KEYS[1]) == ARGV[1] then
            return redis.call("del", KEYS[1])
        else
            return 0
        end
        """
        try:
            await self.redis.eval(script, 1, self.s.lock_name, self._lock_value)
        except Exception as e:
            MET_GC_ERRORS.inc()
            log.error("lock_release_error", error=str(e))
        finally:
            self._lock_held = False
            G_LOCK_HELD.set(0.0)

    # --------------- Queries ---------------
    async def _fetch_orphan_blobs(self, conn: AsyncConnection) -> List[BlobCandidate]:
        cutoff = utcnow() - timedelta(hours=self.s.min_blob_age_hours)
        q = text("""
            SELECT id::text, key, COALESCE(size_bytes,0)::bigint AS size_bytes
            FROM blobs
            WHERE deleted_at IS NULL
              AND ref_count = 0
              AND created_at < :cutoff
            ORDER BY created_at ASC
            LIMIT :lim
        """)
        rows = (await conn.execute(q, {"cutoff": cutoff, "lim": self.s.batch_size})).all()
        return [BlobCandidate(id=r[0], key=r[1], size_bytes=int(r[2])) for r in rows]

    async def _fetch_expired_artifacts(self, conn: AsyncConnection) -> List[ArtifactCandidate]:
        cutoff = utcnow() - timedelta(days=self.s.artifact_retention_days)
        q = text("""
            SELECT a.id::text
            FROM artifacts a
            WHERE a.deleted_at IS NULL
              AND a.pinned = FALSE
              AND a.updated_at < :cutoff
              AND NOT EXISTS (
                    SELECT 1 FROM artifact_blobs ab
                    JOIN blobs b ON b.id = ab.blob_id
                    WHERE ab.artifact_id = a.id
                      AND b.deleted_at IS NULL
              )
            ORDER BY a.updated_at ASC
            LIMIT :lim
        """)
        rows = (await conn.execute(q, {"cutoff": cutoff, "lim": self.s.batch_size})).all()
        return [ArtifactCandidate(id=r[0]) for r in rows]

    async def _fetch_stale_uploads(self, conn: AsyncConnection) -> List[UploadCandidate]:
        cutoff = utcnow() - timedelta(hours=self.s.uploads_ttl_hours)
        q = text("""
            SELECT id::text, key
            FROM uploads
            WHERE finalized = FALSE
              AND created_at < :cutoff
            ORDER BY created_at ASC
            LIMIT :lim
        """)
        rows = (await conn.execute(q, {"cutoff": cutoff, "lim": self.s.batch_size})).all()
        return [UploadCandidate(id=r[0], key=r[1]) for r in rows]

    # --------------- S3 ops ----------------
    def _s3_client_kwargs(self) -> Dict[str, Any]:
        kw: Dict[str, Any] = {}
        if self.s.s3_endpoint_url:
            kw["endpoint_url"] = self.s.s3_endpoint_url
        if self.s.s3_region:
            kw["region_name"] = self.s.s3_region
        if self.s.s3_access_key:
            kw["aws_access_key_id"] = self.s.s3_access_key
        if self.s.s3_secret_key:
            kw["aws_secret_access_key"] = self.s.s3_secret_key
        kw["use_ssl"] = self.s.s3_use_ssl
        return kw

    def _full_key(self, key: str) -> str:
        if self.s.s3_key_prefix:
            return f"{self.s.s3_key_prefix.rstrip('/')}/{key.lstrip('/')}"
        return key.lstrip('/')

    async def _delete_s3_object(self, key: str) -> None:
        if self.s.dry_run:
            return
        full_key = self._full_key(key)
        async with self.s3_session.client("s3", **self._s3_client_kwargs()) as s3:
            # Delete is idempotent; NoSuchKey -> 204 as well
            await s3.delete_object(Bucket=self.s.s3_bucket, Key=full_key)

    # --------------- DB ops ----------------
    async def _soft_delete_blob(self, conn: AsyncConnection, blob_id: str) -> int:
        if self.s.dry_run:
            return 1
        q = text("""
            UPDATE blobs
               SET deleted_at = NOW()
             WHERE id = :id
               AND deleted_at IS NULL
               AND ref_count = 0
        """)
        res = await conn.execute(q, {"id": blob_id})
        return res.rowcount or 0

    async def _hard_delete_artifact(self, conn: AsyncConnection, artifact_id: str) -> int:
        if self.s.dry_run:
            return 1
        # Сначала физически удалить связи, затем пометить артефакт
        await conn.execute(text("DELETE FROM artifact_blobs WHERE artifact_id = :id"), {"id": artifact_id})
        res = await conn.execute(text("UPDATE artifacts SET deleted_at = NOW() WHERE id = :id AND deleted_at IS NULL"), {"id": artifact_id})
        return res.rowcount or 0

    async def _delete_upload_row(self, conn: AsyncConnection, upload_id: str) -> int:
        if self.s.dry_run:
            return 1
        res = await conn.execute(text("DELETE FROM uploads WHERE id = :id"), {"id": upload_id})
        return res.rowcount or 0

    # --------------- Processing ------------
    async def _process_blob(self, conn: AsyncConnection, cand: BlobCandidate) -> Tuple[bool, int]:
        async with self._sem:
            try:
                await async_backoff(self._delete_s3_object, cand.key, max_attempts=4, base_delay=0.2)
                updated = await self._soft_delete_blob(conn, cand.id)
                if updated:
                    MET_GC_BLOBS_DELETED.inc()
                    MET_GC_BYTES_FREED.inc(cand.size_bytes)
                    log.info("blob_deleted", id=cand.id, key=cand.key, bytes=cand.size_bytes, dry_run=self.s.dry_run)
                else:
                    log.warning("blob_delete_skipped", id=cand.id, reason="not_refcount_zero_or_already_deleted")
                return True, updated
            except Exception as e:
                MET_GC_ERRORS.inc()
                log.error("blob_delete_error", id=cand.id, key=cand.key, error=str(e))
                return False, 0

    async def _process_artifact(self, conn: AsyncConnection, cand: ArtifactCandidate) -> Tuple[bool, int]:
        try:
            updated = await self._hard_delete_artifact(conn, cand.id)
            if updated:
                MET_GC_ARTIFACTS_DELETED.inc()
                log.info("artifact_deleted", id=cand.id, dry_run=self.s.dry_run)
            else:
                log.warning("artifact_delete_skipped", id=cand.id, reason="already_deleted_or_raced")
            return True, updated
        except Exception as e:
            MET_GC_ERRORS.inc()
            log.error("artifact_delete_error", id=cand.id, error=str(e))
            return False, 0

    async def _process_upload(self, conn: AsyncConnection, cand: UploadCandidate) -> Tuple[bool, int]:
        async with self._sem:
            try:
                # Попытка удалить объект загрузки в S3 (если был загружен под временным ключом)
                try:
                    await async_backoff(self._delete_s3_object, cand.key, max_attempts=3, base_delay=0.2)
                except Exception as s3e:
                    # Не фатально: файл мог и не существовать
                    log.warning("stale_upload_s3_delete_warn", id=cand.id, key=cand.key, error=str(s3e))
                updated = await self._delete_upload_row(conn, cand.id)
                if updated:
                    MET_GC_UPLOADS_DELETED.inc()
                    log.info("stale_upload_deleted", id=cand.id, key=cand.key, dry_run=self.s.dry_run)
                return True, updated
            except Exception as e:
                MET_GC_ERRORS.inc()
                log.error("stale_upload_delete_error", id=cand.id, error=str(e))
                return False, 0

    # --------------- Run cycles ------------
    async def run_once(self) -> None:
        start = time.perf_counter()
        if not await self.acquire_lock():
            log.info("lock_missed_skip_cycle")
            return
        try:
            async with self.db_engine.connect() as conn:
                await conn.begin()
                blobs = await self._fetch_orphan_blobs(conn)
                arts = await self._fetch_expired_artifacts(conn)
                ups = await self._fetch_stale_uploads(conn)
                await conn.commit()

            log.info("gc_candidates", blobs=len(blobs), artifacts=len(arts), uploads=len(ups))

            # Обрабатываем блобы с параллелизмом и общей транзакцией фиксации soft-delete
            async with self.db_engine.begin() as conn:
                results = await asyncio.gather(*(self._process_blob(conn, b) for b in blobs), return_exceptions=True)
                # результаты уже применены в той же транзакции

            # Артефакты и загрузки — отдельно (операции простые)
            async with self.db_engine.begin() as conn:
                for a in arts:
                    await self._process_artifact(conn, a)
            async with self.db_engine.begin() as conn:
                for u in ups:
                    await self._process_upload(conn, u)

            MET_GC_RUNS.inc()
            dur = time.perf_counter() - start
            MET_GC_DURATION.observe(dur)
            log.info("gc_run_done", duration_sec=round(dur, 3))
        finally:
            await self.release_lock()

    async def run_forever(self) -> None:
        log.info("gc_worker_start", interval=self.s.loop_interval_seconds, dry_run=self.s.dry_run)
        try:
            while not self._shutdown.is_set():
                await self.run_once()
                # Пытаемся поддерживать lock в долгих итерациях
                for _ in range(int(self.s.loop_interval_seconds)):
                    if self._shutdown.is_set():
                        break
                    await self.refresh_lock()
                    await asyncio.sleep(1.0)
        finally:
            log.info("gc_worker_stop")

    def request_shutdown(self) -> None:
        self._shutdown.set()

# ---- Entrypoint ---------------------------------------------------------------
async def _run(settings: Settings, run_once: bool) -> int:
    worker = RegistryGCWorker(settings)
    await worker.start_http()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, worker.request_shutdown)

    code = 0
    try:
        if run_once:
            await worker.run_once()
        else:
            await worker.run_forever()
    except Exception as e:
        MET_GC_ERRORS.inc()
        log.error("fatal_error", error=str(e))
        code = 2
    finally:
        await worker.stop_http()
        with contextlib.suppress(Exception):
            await worker.redis.close()
        with contextlib.suppress(Exception):
            await worker.db_engine.dispose()
    return code

def _parse_argv() -> Tuple[Settings, bool]:
    import argparse

    parser = argparse.ArgumentParser(description="NeuroForge Registry GC Worker")
    parser.add_argument("--run-once", action="store_true", help="Run single GC pass and exit")
    parser.add_argument("--dry-run", action="store_true", help="Do not modify S3/DB")
    parser.add_argument("--db-dsn", type=str, default=None)
    parser.add_argument("--redis-url", type=str, default=None)
    parser.add_argument("--s3-bucket", type=str, default=None)
    parser.add_argument("--s3-endpoint-url", type=str, default=None)
    parser.add_argument("--s3-access-key", type=str, default=None)
    parser.add_argument("--s3-secret-key", type=str, default=None)
    parser.add_argument("--s3-region", type=str, default=None)
    parser.add_argument("--s3-key-prefix", type=str, default=None)
    parser.add_argument("--interval", type=int, default=None)
    parser.add_argument("--batch-size", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--min-blob-age-hours", type=int, default=None)
    parser.add_argument("--artifact-retention-days", type=int, default=None)
    parser.add_argument("--uploads-ttl-hours", type=int, default=None)
    parser.add_argument("--http-port", type=int, default=None)

    args = parser.parse_args()

    s = Settings()  # env first
    # CLI overrides
    kwargs = {}
    for name in (
        "db_dsn", "redis_url", "s3_bucket", "s3_endpoint_url", "s3_access_key", "s3_secret_key",
        "s3_region", "s3_key_prefix",
    ):
        val = getattr(args, name.replace("-", "_"), None)
        if val:
            kwargs[name] = val
    for name in (
        ("loop_interval_seconds", "interval"),
        ("batch_size", "batch_size"),
        ("concurrency", "concurrency"),
        ("min_blob_age_hours", "min_blob_age_hours"),
        ("artifact_retention_days", "artifact_retention_days"),
        ("uploads_ttl_hours", "uploads_ttl_hours"),
        ("http_port", "http_port"),
    ):
        target, argname = name
        val = getattr(args, argname, None)
        if val is not None:
            kwargs[target] = val

    if args.dry_run:
        kwargs["dry_run"] = True

    if kwargs:
        s = s.model_copy(update=kwargs) if hasattr(s, "model_copy") else s.copy(update=kwargs)  # pydantic v2/v1

    return s, bool(args.run_once)

def main() -> None:
    settings, run_once = _parse_argv()
    # Быстрая валидация обязательных параметров
    missing = []
    for k in ("db_dsn", "redis_url", "s3_bucket"):
        if not getattr(settings, k, None):
            missing.append(k)
    if missing:
        log.error("missing_required_settings", fields=missing)
        sys.exit(2)

    try:
        asyncio.run(_run(settings, run_once))
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
