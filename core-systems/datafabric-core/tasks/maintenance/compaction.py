# -*- coding: utf-8 -*-
"""
DataFabric Maintenance: Compaction
----------------------------------

Асинхронная компакция мелких файлов в дата-папках:
- Поддержка локального FS (из коробки), точки расширения под S3/HDFS
- Планирование батчей по целевому размеру/возрасту/паттернам
- Обработчики: CSV (pandas/stdlib), Parquet (pyarrow, если доступен), Binary (конкатенация c перевыравниванием)
- Атомарная запись через временные файлы + fsync + rename
- Манифест и чекпоинты для идемпотентности
- Файловая блокировка каталога
- Метрики и структурированные логи
- Dry-run и режим только планирования

Внешние зависимости: НЕ требуются.
Опционально: pandas, pyarrow

© DataFabric Core. MIT License.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import csv
import dataclasses
import fnmatch
import hashlib
import json
import logging
import os
import pathlib
import random
import shutil
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Protocol, runtime_checkable

# Optional imports (activated automatically if present)
try:
    import pandas as _pd  # type: ignore
except Exception:
    _pd = None

try:
    import pyarrow as _pa  # type: ignore
    import pyarrow.parquet as _pq  # type: ignore
except Exception:
    _pa = None
    _pq = None


logger = logging.getLogger("datafabric.tasks.maintenance.compaction")
if not logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
    logger.addHandler(h)
logger.setLevel(logging.INFO)


# ============================== Exceptions ===================================

class CompactionError(Exception):
    """Базовая ошибка компакции."""


class LockError(CompactionError):
    """Ошибка блокировки каталога."""


# =============================== Config ======================================

@dataclass(frozen=True)
class CompactionConfig:
    root: str                                 # корень данных (каталог)
    include_glob: Tuple[str, ...] = ("**/*.csv", "**/*.parquet", "**/*.bin")
    exclude_glob: Tuple[str, ...] = tuple()
    min_file_bytes: int = 64 * 1024           # порог "мелкого" файла
    target_file_bytes: int = 256 * 1024 * 1024  # целевой размер компакта
    max_batch_files: int = 500
    min_file_age_seconds: int = 5 * 60        # файл должен быть старше N секунд
    max_concurrency: int = 4
    dry_run: bool = False
    plan_only: bool = False
    preserve_originals: bool = False          # если True — исходники не удаляются (для отладки)
    output_suffix: str = ".compact"           # добавляется к имени итогового файла
    manifest_dirname: str = "_compaction"     # системный служебный каталог
    lock_filename: str = ".compaction.lock"
    job_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    checkpoint_every_batches: int = 10
    fail_fast: bool = False                   # останавливать процесс при первом исключении
    partition_depth: int = 0                  # если >0, группировать по N уровней каталогов от root


@dataclass
class CompactionPlanItem:
    partition_key: str
    files: List[pathlib.Path]
    total_bytes: int
    output_path: pathlib.Path
    handler: str                              # "csv"|"parquet"|"binary"


@dataclass
class CompactionMetrics:
    planned_batches: int = 0
    processed_batches: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    files_in: int = 0
    files_out: int = 0
    duration_seconds: float = 0.0
    failures: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


# =============================== Storage =====================================

@runtime_checkable
class Storage(Protocol):
    def abspath(self, p: pathlib.Path) -> pathlib.Path: ...
    def exists(self, p: pathlib.Path) -> bool: ...
    def list_glob(self, root: pathlib.Path, pattern: str) -> Iterable[pathlib.Path]: ...
    def size(self, p: pathlib.Path) -> int: ...
    def mtime(self, p: pathlib.Path) -> float: ...
    def open_read(self, p: pathlib.Path): ...
    def open_write_atomic(self, p: pathlib.Path):
        """
        Должен вернуть файловый объект для записи в временный файл с дальнейшим атомарным rename.
        Реализация ниже в LocalFSStorage.
        """
        ...
    def remove(self, p: pathlib.Path) -> None: ...
    def rename_atomic(self, tmp: pathlib.Path, dst: pathlib.Path) -> None: ...
    def makedirs(self, d: pathlib.Path) -> None: ...


class LocalFSStorage(Storage):
    def abspath(self, p: pathlib.Path) -> pathlib.Path:
        return p.resolve()

    def exists(self, p: pathlib.Path) -> bool:
        return p.exists()

    def list_glob(self, root: pathlib.Path, pattern: str) -> Iterable[pathlib.Path]:
        yield from root.glob(pattern)

    def size(self, p: pathlib.Path) -> int:
        return p.stat().st_size

    def mtime(self, p: pathlib.Path) -> float:
        return p.stat().st_mtime

    def open_read(self, p: pathlib.Path):
        return open(p, "rb", buffering=1024 * 1024)

    def open_write_atomic(self, p: pathlib.Path):
        tmp_dir = p.parent
        os.makedirs(tmp_dir, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=".tmp_compact_", dir=str(tmp_dir))
        f = os.fdopen(fd, "wb", buffering=1024 * 1024)
        f._tmp_target = pathlib.Path(tmp_path)  # type: ignore
        f._final_target = p  # type: ignore
        return f

    def remove(self, p: pathlib.Path) -> None:
        with contextlib.suppress(FileNotFoundError):
            p.unlink()

    def rename_atomic(self, tmp: pathlib.Path, dst: pathlib.Path) -> None:
        # fsync на директорию для надежности
        fdir = os.open(str(dst.parent), os.O_RDONLY)
        try:
            os.replace(str(tmp), str(dst))
            os.fsync(fdir)
        finally:
            os.close(fdir)

    def makedirs(self, d: pathlib.Path) -> None:
        os.makedirs(d, exist_ok=True)


# Заглушка под S3 (для дальнейшей реализации с boto3/aioboto3)
class S3Storage(Storage):
    def __init__(self, bucket: str, prefix: str = "") -> None:
        raise NotImplementedError("S3Storage is a placeholder. Implement with boto3/aioboto3.")


# ============================= File Handlers =================================

class FileHandler(Protocol):
    name: str
    def can_handle(self, paths: Sequence[pathlib.Path]) -> bool: ...
    def make_output_name(self, plan: CompactionPlanItem) -> pathlib.Path: ...
    def merge(self, storage: Storage, plan: CompactionPlanItem) -> Tuple[int, int]:
        """
        Выполняет слияние файлов плана.
        Возвращает (bytes_in, bytes_out).
        """
        ...


class CSVHandler:
    name = "csv"

    def can_handle(self, paths: Sequence[pathlib.Path]) -> bool:
        return all(str(p).lower().endswith(".csv") for p in paths)

    def make_output_name(self, plan: CompactionPlanItem) -> pathlib.Path:
        base = plan.output_path.with_suffix("")
        return base.with_suffix(".csv")

    def merge(self, storage: Storage, plan: CompactionPlanItem) -> Tuple[int, int]:
        # Если есть pandas — используем concat (быстрее и безопаснее по типам)
        if _pd is not None:
            frames = []
            bytes_in = 0
            for p in plan.files:
                bytes_in += storage.size(p)
                frames.append(_pd.read_csv(p, dtype=str))
            out_df = _pd.concat(frames, ignore_index=True) if frames else _pd.DataFrame()
            out_path = self.make_output_name(plan)
            tmp_f = storage.open_write_atomic(out_path)  # type: ignore
            try:
                out_df.to_csv(tmp_f, index=False)
                tmp_f.flush()
                os.fsync(tmp_f.fileno())
            finally:
                tmp = tmp_f._tmp_target  # type: ignore
                tmp_f.close()
            storage.rename_atomic(tmp, out_path)
            return bytes_in, storage.size(out_path)
        # Без pandas — стандартный csv: копируем заголовок один раз, далее строки
        header_written = False
        bytes_in = 0
        out_path = self.make_output_name(plan)
        tmp_f = storage.open_write_atomic(out_path)  # type: ignore
        try:
            writer = None
            for idx, p in enumerate(plan.files):
                bytes_in += storage.size(p)
                with storage.open_read(p) as f_in:
                    # определяем заголовок
                    text_iter = (line.decode("utf-8", errors="ignore") for line in iter(lambda: f_in.read(1024 * 1024), b""))
                    # переписываем по строкам, но корректнее — через csv.reader
                # Перечитаем файлы через текстовый режим для корректного CSV
                with open(p, "r", newline="", encoding="utf-8", errors="ignore") as tf:
                    rdr = csv.reader(tf)
                    rows = list(rdr)
                    if not rows:
                        continue
                    header, data = rows[0], rows[1:]
                    if not header_written:
                        writer = csv.writer(tmp_f)  # type: ignore
                        writer.writerow(header)
                        header_written = True
                    # Записываем данные
                    for row in data:
                        writer.writerow(row)
            tmp_f.flush()
            os.fsync(tmp_f.fileno())
        finally:
            tmp = tmp_f._tmp_target  # type: ignore
            tmp_f.close()
        storage.rename_atomic(tmp, out_path)
        return bytes_in, storage.size(out_path)


class ParquetHandler:
    name = "parquet"

    def can_handle(self, paths: Sequence[pathlib.Path]) -> bool:
        return all(str(p).lower().endswith(".parquet") for p in paths)

    def make_output_name(self, plan: CompactionPlanItem) -> pathlib.Path:
        base = plan.output_path.with_suffix("")
        return base.with_suffix(".parquet")

    def merge(self, storage: Storage, plan: CompactionPlanItem) -> Tuple[int, int]:
        if _pq is None or _pa is None:
            raise CompactionError("pyarrow/pyarrow.parquet not available for Parquet compaction.")
        tables = []
        bytes_in = 0
        for p in plan.files:
            bytes_in += storage.size(p)
            with storage.open_read(p) as f:
                table = _pq.read_table(f)
                tables.append(table)
        table_out = _pa.concat_tables(tables, promote=False) if tables else _pa.table({})
        out_path = self.make_output_name(plan)
        tmp_f = storage.open_write_atomic(out_path)  # type: ignore
        try:
            _pq.write_table(table_out, tmp_f)
            tmp_f.flush()
            os.fsync(tmp_f.fileno())
        finally:
            tmp = tmp_f._tmp_target  # type: ignore
            tmp_f.close()
        storage.rename_atomic(tmp, out_path)
        return bytes_in, storage.size(out_path)


class BinaryHandler:
    name = "binary"

    def can_handle(self, paths: Sequence[pathlib.Path]) -> bool:
        return all(str(p).lower().endswith(".bin") for p in paths)

    def make_output_name(self, plan: CompactionPlanItem) -> pathlib.Path:
        base = plan.output_path.with_suffix("")
        return base.with_suffix(".bin")

    def merge(self, storage: Storage, plan: CompactionPlanItem) -> Tuple[int, int]:
        # Простая безопасная конкатенация с разделителем новой строки при необходимости
        out_path = self.make_output_name(plan)
        tmp_f = storage.open_write_atomic(out_path)  # type: ignore
        bytes_in = 0
        try:
            prev_ended_nl = True
            for p in plan.files:
                with storage.open_read(p) as f_in:
                    while True:
                        chunk = f_in.read(4 * 1024 * 1024)
                        if not chunk:
                            break
                        tmp_f.write(chunk)
                        bytes_in += len(chunk)
                    # добавляем перевод строки между файлами, если нет
                with open(p, "rb") as chk:
                    chk.seek(0, os.SEEK_END)
                    if chk.tell() > 0:
                        chk.seek(-1, os.SEEK_END)
                        last = chk.read(1)
                        prev_ended_nl = last == b"\n"
                if not prev_ended_nl:
                    tmp_f.write(b"\n")
                    prev_ended_nl = True
            tmp_f.flush()
            os.fsync(tmp_f.fileno())
        finally:
            tmp = tmp_f._tmp_target  # type: ignore
            tmp_f.close()
        storage.rename_atomic(tmp, out_path)
        return bytes_in, storage.size(out_path)


# ============================== Planner ======================================

class CompactionPlanner:
    def __init__(self, cfg: CompactionConfig, storage: Storage) -> None:
        self.cfg = cfg
        self.storage = storage

    def scan(self) -> List[pathlib.Path]:
        root = pathlib.Path(self.cfg.root)
        files: List[pathlib.Path] = []
        # include
        for pat in self.cfg.include_glob:
            files.extend(self.storage.list_glob(root, pat))
        # exclude
        excl: List[pathlib.Path] = []
        for pat in self.cfg.exclude_glob:
            excl.extend(self.storage.list_glob(root, pat))
        excl_set = {p.resolve() for p in excl}
        # системный каталог исключаем всегда
        excl_set.add((root / self.cfg.manifest_dirname).resolve())
        # фильтрация
        filt = []
        now = time.time()
        for p in files:
            rp = p.resolve()
            if any(str(rp).startswith(str(es)) for es in excl_set):
                continue
            try:
                sz = self.storage.size(p)
                age_ok = (now - self.storage.mtime(p)) >= self.cfg.min_file_age_seconds
            except FileNotFoundError:
                continue
            if sz <= 0:
                continue
            if sz <= self.cfg.min_file_bytes and age_ok:
                filt.append(p)
        return sorted(set(filt))

    def _partition_key(self, p: pathlib.Path) -> str:
        if self.cfg.partition_depth <= 0:
            return ""
        # относительный путь от root
        rel = pathlib.Path(self.cfg.root).resolve()
        try:
            rp = p.resolve().relative_to(rel)
        except Exception:
            return ""
        parts = rp.parts[:-1]  # без имени файла
        return "/".join(parts[: self.cfg.partition_depth])

    def _handler_for(self, candidates: Sequence[pathlib.Path]) -> Optional[str]:
        if not candidates:
            return None
        exts = {p.suffix.lower() for p in candidates}
        if exts == {".csv"}:
            return "csv"
        if exts == {".parquet"}:
            return "parquet"
        if exts == {".bin"}:
            return "binary"
        return None

    def build_plan(self) -> List[CompactionPlanItem]:
        small = self.scan()
        if not small:
            return []

        # группировка по partition_key и расширению
        buckets: Dict[Tuple[str, str], List[pathlib.Path]] = {}
        for p in small:
            key = (self._partition_key(p), p.suffix.lower())
            buckets.setdefault(key, []).append(p)

        plan: List[CompactionPlanItem] = []
        for (pk, ext), paths in buckets.items():
            paths = sorted(paths)  # стабильность планов
            # greedily упаковываем по target_file_bytes и max_batch_files
            cur_group: List[pathlib.Path] = []
            cur_bytes = 0
            for p in paths:
                sz = self.storage.size(p)
                if cur_group and (cur_bytes + sz > self.cfg.target_file_bytes or len(cur_group) >= self.cfg.max_batch_files):
                    out_name = self._output_name(pk, cur_group, ext)
                    handler = self._handler_for(cur_group)
                    if handler:
                        plan.append(CompactionPlanItem(
                            partition_key=pk,
                            files=cur_group,
                            total_bytes=cur_bytes,
                            output_path=out_name,
                            handler=handler,
                        ))
                    cur_group, cur_bytes = [], 0
                cur_group.append(p)
                cur_bytes += sz
            if cur_group:
                out_name = self._output_name(pk, cur_group, ext)
                handler = self._handler_for(cur_group)
                if handler:
                    plan.append(CompactionPlanItem(
                        partition_key=pk,
                        files=cur_group,
                        total_bytes=cur_bytes,
                        output_path=out_name,
                        handler=handler,
                    ))
        return plan

    def _output_name(self, partition_key: str, files: Sequence[pathlib.Path], ext: str) -> pathlib.Path:
        # базовый путь: root/(partition_key)/_compaction/<hash>.<ext> + suffix
        root = pathlib.Path(self.cfg.root)
        subdir = root / (partition_key if partition_key else "") / self.cfg.manifest_dirname
        self.storage.makedirs(subdir)
        h = hashlib.sha256((",".join(sorted(str(f) for f in files))).encode("utf-8")).hexdigest()[:16]
        base = subdir / f"compact_{h}{self.cfg.output_suffix}{ext}"
        return base


# ============================== Lock/Manifest ================================

class DirectoryLock:
    def __init__(self, storage: Storage, root: pathlib.Path, lock_filename: str) -> None:
        self.storage = storage
        self.lock_path = root / lock_filename
        self._fd: Optional[int] = None

    def acquire(self) -> None:
        if self.storage.exists(self.lock_path):
            raise LockError(f"Lock exists: {self.lock_path}")
        # создаем lock-файл
        fd = os.open(str(self.lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        os.write(fd, f"{os.getpid()}:{time.time()}".encode("ascii"))
        os.close(fd)

    def release(self) -> None:
        self.storage.remove(self.lock_path)


@dataclass
class Manifest:
    job_id: str
    created_at: float
    items: List[Dict[str, Any]] = field(default_factory=list)

    def add(self, item: CompactionPlanItem, status: str, bytes_in: int = 0, bytes_out: int = 0, error: Optional[str] = None) -> None:
        self.items.append({
            "partition_key": item.partition_key,
            "output": str(item.output_path),
            "handler": item.handler,
            "files": [str(x) for x in item.files],
            "total_bytes": item.total_bytes,
            "status": status,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "error": error,
            "ts": time.time(),
        })

    def save(self, storage: Storage, root: pathlib.Path, dirname: str) -> None:
        d = root / dirname
        storage.makedirs(d)
        p = d / f"manifest_{self.job_id}.json"
        tmp = p.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(dataclasses.asdict(self), f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)


# ============================== Executor =====================================

class CompactionExecutor:
    def __init__(self, cfg: CompactionConfig, storage: Optional[Storage] = None) -> None:
        self.cfg = cfg
        self.storage = storage or LocalFSStorage()
        self.handlers: Dict[str, FileHandler] = {
            "csv": CSVHandler(),
            "parquet": ParquetHandler(),
            "binary": BinaryHandler(),
        }
        self.metrics = CompactionMetrics()
        self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, cfg.max_concurrency))

    async def _run_in_pool(self, fn, *args, **kwargs):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._pool, lambda: fn(*args, **kwargs))

    async def execute(self) -> CompactionMetrics:
        t0 = time.time()
        root = pathlib.Path(self.cfg.root).resolve()
        lock = DirectoryLock(self.storage, root, self.cfg.lock_filename)
        manifest = Manifest(job_id=self.cfg.job_id, created_at=t0)

        logger.info("Compaction start: root=%s job=%s", root, self.cfg.job_id)
        lock.acquire()
        try:
            planner = CompactionPlanner(self.cfg, self.storage)
            plan = planner.build_plan()
            self.metrics.planned_batches = len(plan)
            if self.cfg.plan_only or self.cfg.dry_run:
                logger.info("Plan generated: %d batches (dry_run=%s, plan_only=%s)", len(plan), self.cfg.dry_run, self.cfg.plan_only)
                manifest.save(self.storage, root, self.cfg.manifest_dirname)
                self.metrics.duration_seconds = time.time() - t0
                return self.metrics

            sem = asyncio.Semaphore(self.cfg.max_concurrency)
            idx = 0

            async def _process(item: CompactionPlanItem):
                nonlocal idx
                async with sem:
                    handler = self.handlers.get(item.handler)
                    if handler is None:
                        manifest.add(item, "skipped", error="no_handler")
                        return
                    try:
                        if self.cfg.dry_run:
                            manifest.add(item, "dry_run")
                            return
                        bytes_in, bytes_out = await self._run_in_pool(handler.merge, self.storage, item)
                        self.metrics.files_in += len(item.files)
                        self.metrics.bytes_in += bytes_in
                        self.metrics.bytes_out += bytes_out
                        self.metrics.files_out += 1
                        # удаляем исходники при необходимости
                        if not self.cfg.preserve_originals:
                            for p in item.files:
                                self.storage.remove(p)
                        manifest.add(item, "ok", bytes_in=bytes_in, bytes_out=bytes_out)
                        self.metrics.processed_batches += 1
                    except Exception as e:
                        self.metrics.failures += 1
                        manifest.add(item, "failed", error=str(e))
                        logger.exception("Batch failed: %s", e)
                        if self.cfg.fail_fast:
                            raise

                    idx += 1
                    if self.cfg.checkpoint_every_batches and idx % self.cfg.checkpoint_every_batches == 0:
                        manifest.save(self.storage, root, self.cfg.manifest_dirname)

            await asyncio.gather(*[_process(it) for it in plan])
            manifest.save(self.storage, root, self.cfg.manifest_dirname)
        finally:
            with contextlib.suppress(Exception):
                lock.release()
            self._pool.shutdown(wait=True)
            self.metrics.duration_seconds = time.time() - t0
            logger.info("Compaction done: %s", self.metrics.to_dict())
        return self.metrics


# ============================== CLI / Selftest ================================

async def _selftest(tmpdir: Optional[str] = None) -> None:
    td = pathlib.Path(tmpdir or tempfile.mkdtemp(prefix="df_compact_"))
    data = td / "dataset" / "dt=2025-08-15"
    os.makedirs(data, exist_ok=True)
    # создаем много мелких CSV
    for i in range(25):
        p = data / f"part-{i:05d}.csv"
        with open(p, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["id", "val"])
            for j in range(20):
                w.writerow([f"{i}-{j}", random.randint(0, 1000)])
        os.utime(p, (time.time() - 3600, time.time() - 3600))

    cfg = CompactionConfig(
        root=str(td / "dataset"),
        include_glob=("**/*.csv",),
        target_file_bytes=512 * 1024,
        min_file_bytes=4 * 1024,
        max_concurrency=2,
        partition_depth=1,
        dry_run=False,
        plan_only=False,
        preserve_originals=False,
        checkpoint_every_batches=2,
    )
    ex = CompactionExecutor(cfg)
    m = await ex.execute()
    print("Selftest metrics:", json.dumps(m.to_dict(), indent=2))

if __name__ == "__main__":  # pragma: no cover
    try:
        asyncio.run(_selftest())
    except KeyboardInterrupt:
        pass
