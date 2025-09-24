# oblivionvault/oblivionvault/executors/purge.py
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
import time
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import AsyncIterator, Iterable, Optional, Protocol, Sequence, Tuple

# ---------------------------
# Settings (external integration)
# ---------------------------
try:
    from oblivionvault.settings import get_settings  # type: ignore
except Exception:  # pragma: no cover
    def get_settings():  # minimal fallback
        class _S:
            app_name = "oblivionvault-core"
            env = os.getenv("APP_ENV", "dev")
            logging = type("L", (), {"level": os.getenv("LOG_LEVEL", "INFO"), "json": True, "include_pid": True, "include_hostname": True})
            observability = type("O", (), {
                "enable_metrics": True,
                "prometheus_multiproc_dir": None,
                "enable_otel": False,
                "otlp_endpoint": None,
                "service_name": "oblivionvault-core",
            })
            storage = type("ST", (), {
                "backend": "filesystem" if os.getenv("OBLIVIONVAULT_FS_ROOT") else "memory",
                "fs": type("FS", (), {"root": Path(os.getenv("OBLIVIONVAULT_FS_ROOT", "/var/lib/oblivionvault"))}),
            })
        return _S()

# ---------------------------
# Repo/Storage Protocols
# ---------------------------

class VersionRef(Protocol):
    archive_id: str
    version_id: str
    path: Optional[Path]  # None для in-memory
    size: Optional[int]
    created_at: datetime

class ArchiveRef(Protocol):
    id: str
    updated_at: datetime
    deleted: bool

class ArchiveRepoProtocol(Protocol):
    """Абстракция репозитория метаданных. Должна быть реализована реальным слоем хранения (БД)."""

    async def find_soft_deleted(self, older_than: datetime, limit: int) -> Sequence[ArchiveRef]: ...
    async def list_versions(self, archive_id: str) -> Sequence[VersionRef]: ...
    async def hard_delete_archive(self, archive_id: str) -> None: ...
    async def referenced_paths(self) -> AsyncIterator[Path]:
        """Поток всех путей файлов стораджа, известных репозиторию (для orphan-GC)."""
        ...

class StorageBackendProtocol(Protocol):
    """Абстракция стораджа двоичных данных."""

    async def delete(self, ref: VersionRef) -> None: ...
    async def exists(self, ref: VersionRef) -> bool: ...
    async def walk_all_paths(self) -> AsyncIterator[Path]:
        """Итерация по всем файлам в сторадже (для orphan-GC)."""
        ...

# ---------------------------
# Logging
# ---------------------------

def _configure_logging_json(level: str) -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    logging.basicConfig(
        level=lvl,
        handlers=[handler],
        format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
    )

log = logging.getLogger("oblivionvault.executor.purge")

# ---------------------------
# Prometheus textfile collector (optional)
# ---------------------------

class Metrics:
    def __init__(self, textfile_dir: Optional[Path]) -> None:
        self.textfile_dir = textfile_dir
        self.reset()

    def reset(self) -> None:
        self.deleted_versions = 0
        self.deleted_archives = 0
        self.orphan_files_deleted = 0
        self.errors = 0
        self.start = time.time()

    def incr_deleted_version(self, n: int = 1) -> None:
        self.deleted_versions += n

    def incr_deleted_archive(self, n: int = 1) -> None:
        self.deleted_archives += n

    def incr_orphan(self, n: int = 1) -> None:
        self.orphan_files_deleted += n

    def incr_error(self, n: int = 1) -> None:
        self.errors += n

    def write_textfile(self, filename: str = "oblivionvault_purge.prom") -> None:
        if not self.textfile_dir:
            return
        try:
            self.textfile_dir.mkdir(parents=True, exist_ok=True)
            p = self.textfile_dir / filename
            elapsed = max(time.time() - self.start, 0.0001)
            content = []
            content.append(f'# HELP oblivionvault_purge_deleted_versions Total deleted versions\n# TYPE oblivionvault_purge_deleted_versions counter\noblivionvault_purge_deleted_versions {self.deleted_versions}')
            content.append(f'# HELP oblivionvault_purge_deleted_archives Total deleted archives\n# TYPE oblivionvault_purge_deleted_archives counter\noblivionvault_purge_deleted_archives {self.deleted_archives}')
            content.append(f'# HELP oblivionvault_purge_orphan_files_deleted Total orphan files deleted\n# TYPE oblivionvault_purge_orphan_files_deleted counter\noblivionvault_purge_orphan_files_deleted {self.orphan_files_deleted}')
            content.append(f'# HELP oblivionvault_purge_errors Total errors during purge\n# TYPE oblivionvault_purge_errors counter\noblivionvault_purge_errors {self.errors}')
            content.append(f'# HELP oblivionvault_purge_elapsed_seconds Execution time seconds\n# TYPE oblivionvault_purge_elapsed_seconds gauge\noblivionvault_purge_elapsed_seconds {elapsed}')
            p.write_text("\n".join(content) + "\n", encoding="utf-8")
        except Exception:
            # метрики не должны ломать выполнение
            log.warning("failed to write textfile metrics", exc_info=False)

# ---------------------------
# File lease (distributed single-runner)
# ---------------------------

class FileLease:
    """Простой файловый лизинг с истечением TTL, атомарный через O_EXCL."""
    def __init__(self, lock_path: Path, ttl_seconds: int = 600) -> None:
        self.lock_path = lock_path
        self.ttl = ttl_seconds
        self._have_lock = False

    async def acquire(self) -> bool:
        now = int(time.time())
        # если файл существует и не протух — выходим
        if self.lock_path.exists():
            with suppress(Exception):
                txt = self.lock_path.read_text(encoding="utf-8").strip()
                exp = int(txt or "0")
                if now < exp:
                    return False
            # протух — пытаемся убрать
            with suppress(Exception):
                self.lock_path.unlink()

        # атомарная установка
        try:
            self.lock_path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o640)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(str(now + self.ttl))
            self._have_lock = True
            return True
        except FileExistsError:
            return False

    async def refresh(self) -> None:
        if not self._have_lock:
            return
        with suppress(Exception):
            now = int(time.time())
            self.lock_path.write_text(str(now + self.ttl), encoding="utf-8")

    async def release(self) -> None:
        if not self._have_lock:
            return
        with suppress(Exception):
            self.lock_path.unlink()
        self._have_lock = False

# ---------------------------
# Purge configuration
# ---------------------------

@dataclass
class PurgeConfig:
    dry_run: bool = bool(os.getenv("PURGE_DRY_RUN", "true").lower() == "true")
    max_batch: int = int(os.getenv("PURGE_MAX_BATCH", "200"))
    concurrency: int = int(os.getenv("PURGE_CONCURRENCY", "8"))
    soft_delete_ttl_days: int = int(os.getenv("PURGE_SOFT_DELETE_TTL_DAYS", "7"))
    orphan_ttl_hours: int = int(os.getenv("PURGE_ORPHAN_TTL_HOURS", "1"))
    loop_interval_seconds: int = int(os.getenv("PURGE_LOOP_INTERVAL_SECONDS", "0"))  # 0 = single run
    stop_on_error: bool = bool(os.getenv("PURGE_STOP_ON_ERROR", "false").lower() == "true")
    lock_ttl_seconds: int = int(os.getenv("PURGE_LOCK_TTL_SECONDS", "600"))
    lock_path: Path = Path(os.getenv("PURGE_LOCK_PATH", "/tmp/oblivionvault_purge.lock"))
    textfile_dir: Optional[Path] = Path(os.getenv("PROMETHEUS_TEXTFILE_DIR")) if os.getenv("PROMETHEUS_TEXTFILE_DIR") else None

# ---------------------------
# Default FS storage implementing StorageBackendProtocol
# ---------------------------

class FSStorage(StorageBackendProtocol):
    def __init__(self, root: Path) -> None:
        self.root = root

    async def delete(self, ref: VersionRef) -> None:
        if not ref.path:
            return
        p = Path(ref.path)
        if p.is_file():
            with suppress(Exception):
                p.unlink()
            # пробуем чистить пустые родительские директории
            with suppress(Exception):
                parent = p.parent
                if parent.exists() and not any(parent.iterdir()):
                    parent.rmdir()

    async def exists(self, ref: VersionRef) -> bool:
        return bool(ref.path and Path(ref.path).is_file())

    async def walk_all_paths(self) -> AsyncIterator[Path]:
        if not self.root.exists():
            return
        # Используем неблокирующий обход через отдельный поток
        for dirpath, _, filenames in await asyncio.to_thread(lambda: list(os.walk(self.root))):
            for name in filenames:
                yield Path(dirpath) / name

# ---------------------------
# Core purge logic
# ---------------------------

class PurgeExecutor:
    def __init__(self, repo: ArchiveRepoProtocol, storage: StorageBackendProtocol, cfg: PurgeConfig, metrics: Metrics) -> None:
        self.repo = repo
        self.storage = storage
        self.cfg = cfg
        self.metrics = metrics
        self.sem = asyncio.Semaphore(self.cfg.concurrency)

    async def purge_soft_deleted(self) -> None:
        older_than = datetime.now(timezone.utc) - timedelta(days=self.cfg.soft_delete_ttl_days)
        total = 0
        while True:
            batch = await self.repo.find_soft_deleted(older_than=older_than, limit=self.cfg.max_batch)
            if not batch:
                break
            log.info("found soft-deleted batch", extra={"count": len(batch)})
            await self._process_archives_batch(batch)
            total += len(batch)
            if len(batch) < self.cfg.max_batch:
                break
        log.info("soft-deleted purge completed", extra={"archives_processed": total})

    async def _process_archives_batch(self, archives: Sequence[ArchiveRef]) -> None:
        async def handle(arch: ArchiveRef) -> None:
            async with self.sem:
                try:
                    versions = await self.repo.list_versions(arch.id)
                    # сначала удаляем версии в сторадже
                    for v in versions:
                        if self.cfg.dry_run:
                            log.info("dry-run delete version", extra={"archive_id": v.archive_id, "version_id": v.version_id, "path": str(v.path) if v.path else None})
                        else:
                            if await self.storage.exists(v):
                                await self.storage.delete(v)
                                self.metrics.incr_deleted_version()
                                log.info("deleted version data", extra={"archive_id": v.archive_id, "version_id": v.version_id})
                    # затем чистим метаданные архива
                    if self.cfg.dry_run:
                        log.info("dry-run hard-delete archive", extra={"archive_id": arch.id})
                    else:
                        await self.repo.hard_delete_archive(arch.id)
                        self.metrics.incr_deleted_archive()
                        log.info("hard-deleted archive", extra={"archive_id": arch.id})
                except Exception as e:
                    self.metrics.incr_error()
                    log.error(f"error purging archive {arch.id}: {e}", exc_info=self.cfg.env_dev())
                    if self.cfg.stop_on_error:
                        raise

        await asyncio.gather(*(handle(a) for a in archives))

    async def purge_orphans(self) -> None:
        """Удаляет файлы, которых нет в индексе репозитория и которые старше orphan_ttl_hours."""
        # собираем множество «известных» путей
        known: set[Path] = set()
        async for p in self.repo.referenced_paths():
            known.add(Path(p))

        cutoff = time.time() - (self.cfg.orphan_ttl_hours * 3600)
        async for path in self.storage.walk_all_paths():
            if path not in known:
                try:
                    st = await asyncio.to_thread(path.stat)
                    if st.st_mtime > cutoff:
                        continue  # слишком свежий — пропускаем
                    if self.cfg.dry_run:
                        log.info("dry-run delete orphan", extra={"path": str(path)})
                    else:
                        with suppress(Exception):
                            path.unlink()
                            self.metrics.incr_orphan()
                            log.info("deleted orphan file", extra={"path": str(path)})
                except FileNotFoundError:
                    continue
                except Exception as e:
                    self.metrics.incr_error()
                    log.error(f"error deleting orphan {path}: {e}", exc_info=self.cfg.env_dev())
                    if self.cfg.stop_on_error:
                        raise

# ---------------------------
# Helpers / Config extensions
# ---------------------------

def _env_dev() -> bool:
    try:
        s = get_settings()
        return getattr(s, "is_dev", False) or getattr(s, "env", "dev") == "dev"
    except Exception:
        return True

def _build_cfg_from_env() -> PurgeConfig:
    return PurgeConfig()

PurgeConfig.env_dev = staticmethod(_env_dev)  # type: ignore[attr-defined]

# ---------------------------
# Dummy in-memory repo for tests/dev (optional)
# ---------------------------

# Пример: разработчикам удобно иметь простую реализацию для локальных проверок.
class _DummyVersion:
    def __init__(self, archive_id: str, version_id: str, path: Optional[Path], size: Optional[int], created_at: datetime):
        self.archive_id = archive_id
        self.version_id = version_id
        self.path = path
        self.size = size
        self.created_at = created_at

class _DummyArchive:
    def __init__(self, id: str, deleted: bool, updated_at: datetime, versions: Sequence[_DummyVersion]):
        self.id = id
        self.deleted = deleted
        self.updated_at = updated_at
        self._versions = list(versions)

class DummyRepo(ArchiveRepoProtocol):
    """Dev-only in-memory репо. Не использовать в прод."""
    def __init__(self, root: Path):
        self.archives: list[_DummyArchive] = []
        # создадим один тестовый архив с файлом
        test_file = root / "dummy" / "v1"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_bytes(b"hello")
        v = _DummyVersion("a1", "v1", test_file, test_file.stat().st_size, datetime.now(timezone.utc) - timedelta(days=10))
        self.archives.append(_DummyArchive("a1", deleted=True, updated_at=datetime.now(timezone.utc) - timedelta(days=9), versions=[v]))

    async def find_soft_deleted(self, older_than: datetime, limit: int) -> Sequence[ArchiveRef]:
        res = [a for a in self.archives if a.deleted and a.updated_at < older_than]
        return res[:limit]

    async def list_versions(self, archive_id: str) -> Sequence[VersionRef]:
        for a in self.archives:
            if a.id == archive_id:
                return list(a._versions)
        return []

    async def hard_delete_archive(self, archive_id: str) -> None:
        self.archives = [a for a in self.archives if a.id != archive_id]

    async def referenced_paths(self) -> AsyncIterator[Path]:
        for a in self.archives:
            for v in a._versions:
                if v.path:
                    yield v.path

# ---------------------------
# Wiring
# ---------------------------

async def _build_repo_and_storage() -> Tuple[ArchiveRepoProtocol, StorageBackendProtocol]:
    settings = get_settings()
    # В реальной интеграции здесь создаётся реальный Repo (например, Postgres) и Storage
    # Ниже — дефолт для dev: DummyRepo + FSStorage
    fs_root = getattr(settings.storage.fs, "root", Path("/var/lib/oblivionvault"))
    repo: ArchiveRepoProtocol = DummyRepo(fs_root)  # Замените на боевую реализацию
    storage: StorageBackendProtocol = FSStorage(fs_root)
    return repo, storage

@asynccontextmanager
async def _lease(cfg: PurgeConfig):
    lease = FileLease(cfg.lock_path, ttl_seconds=cfg.lock_ttl_seconds)
    ok = await lease.acquire()
    if not ok:
        log.info("another purge executor holds the lease; exiting")
        yield False
        return
    try:
        yield True
    finally:
        await lease.release()

async def _run_once(executor: PurgeExecutor, cfg: PurgeConfig, metrics: Metrics) -> int:
    metrics.reset()
    try:
        await executor.purge_soft_deleted()
        await executor.purge_orphans()
        return 0
    finally:
        metrics.write_textfile()

async def _run_main(cfg: PurgeConfig) -> int:
    settings = get_settings()
    # логирование
    _configure_logging_json(getattr(settings.logging, "level", "INFO"))

    # инициализация repo/storage
    repo, storage = await _build_repo_and_storage()
    metrics = Metrics(cfg.textfile_dir)
    executor = PurgeExecutor(repo, storage, cfg, metrics)

    stop_event = asyncio.Event()

    def _signal_handler(*_):
        log.info("termination signal received")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        with suppress(Exception):
            asyncio.get_running_loop().add_signal_handler(sig, _signal_handler)

    # лизинг на единственного исполнителя
    async with _lease(cfg) as acquired:
        if not acquired:
            return 0
        # одиночный прогон
        if cfg.loop_interval_seconds <= 0:
            return await _run_once(executor, cfg, metrics)
        # циклический режим
        while not stop_event.is_set():
            rc = await _run_once(executor, cfg, metrics)
            # обновляем лизинг
            with suppress(Exception):
                await asyncio.wait_for(asyncio.create_task(asyncio.shield(asyncio.sleep(0))), timeout=0.01)
            with suppress(Exception):
                await executor.metrics.write_textfile  # type: ignore[attr-defined]
            with suppress(Exception):
                await asyncio.wait_for(asyncio.create_task(asyncio.shield(asyncio.sleep(cfg.loop_interval_seconds))), timeout=cfg.loop_interval_seconds)
            with suppress(Exception):
                # периодически обновляем лизинг
                await asyncio.wait_for(asyncio.create_task(asyncio.shield(asyncio.sleep(0))), timeout=0.01)
        return 0

def _parse_args(argv: Sequence[str]) -> PurgeConfig:
    p = argparse.ArgumentParser(description="OblivionVault Purge Executor")
    p.add_argument("--dry-run", action="store_true", help="Enable dry-run mode")
    p.add_argument("--no-dry-run", action="store_true", help="Disable dry-run mode")
    p.add_argument("--max-batch", type=int, help="Max batch size per cycle")
    p.add_argument("--concurrency", type=int, help="Max concurrent deletions")
    p.add_argument("--soft-delete-ttl-days", type=int, help="TTL in days before hard-deleting soft-deleted archives")
    p.add_argument("--orphan-ttl-hours", type=int, help="Minimum age of orphan files to delete")
    p.add_argument("--loop-interval-seconds", type=int, help="Loop interval, 0 for single run")
    p.add_argument("--stop-on-error", action="store_true", help="Stop on first error")
    p.add_argument("--lock-path", type=str, help="Filesystem lease path")
    p.add_argument("--lock-ttl-seconds", type=int, help="Lease TTL seconds")
    p.add_argument("--textfile-dir", type=str, help="Prometheus textfile collector dir")
    args = p.parse_args(argv)

    cfg = _build_cfg_from_env()

    if args.dry_run:
        cfg.dry_run = True
    if args.no_dry_run:
        cfg.dry_run = False
    if args.max_batch is not None:
        cfg.max_batch = args.max_batch
    if args.concurrency is not None:
        cfg.concurrency = args.concurrency
    if args.soft_delete_ttl_days is not None:
        cfg.soft_delete_ttl_days = args.soft_delete_ttl_days
    if args.orphan_ttl_hours is not None:
        cfg.orphan_ttl_hours = args.orphan_ttl_hours
    if args.loop_interval_seconds is not None:
        cfg.loop_interval_seconds = args.loop_interval_seconds
    if args.stop_on_error:
        cfg.stop_on_error = True
    if args.lock_path:
        cfg.lock_path = Path(args.lock_path)
    if args.lock_ttl_seconds is not None:
        cfg.lock_ttl_seconds = args.lock_ttl_seconds
    if args.textfile_dir:
        cfg.textfile_dir = Path(args.textfile_dir)
    return cfg

def main(argv: Optional[Sequence[str]] = None) -> int:
    cfg = _parse_args(argv if argv is not None else sys.argv[1:])
    return asyncio.run(_run_main(cfg))

if __name__ == "__main__":
    raise SystemExit(main())
