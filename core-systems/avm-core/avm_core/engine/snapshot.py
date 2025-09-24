# файл: core-systems/avm_core/engine/snapshot.py
from __future__ import annotations

import datetime as _dt
import gzip
import hashlib
import hmac
import io
import json
import logging
import os
import platform
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, MutableMapping, Optional, Protocol, Sequence, Tuple, Union, runtime_checkable
from uuid import uuid4


# =========================
# Константы и конфигурация
# =========================

SNAPSHOT_VERSION = "1.0"
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024  # 4 MiB
PACK_FILENAME = "data.pack.gz"        # gzip из stdlib (без внешних зависимостей)
MANIFEST_FILENAME = "manifest.json"
LOCK_FILENAME = ".lock"
ENV_HMAC_KEY = "AVM_CORE_SNAPSHOT_HMAC_KEY"

_logger = logging.getLogger("avm_core.engine.snapshot")


# ======================
# Протоколы абстракций
# ======================

@runtime_checkable
class BlockReader(Protocol):
    """Абстракция источника блочного устройства/образа диска для чтения."""
    def size_bytes(self) -> int: ...
    def read_at(self, offset: int, length: int) -> bytes: ...


@runtime_checkable
class BlockWriter(Protocol):
    """Абстракция приёмника данных при восстановлении."""
    def size_bytes(self) -> int: ...
    def write_at(self, offset: int, data: bytes) -> None: ...
    def flush(self) -> None: ...


@runtime_checkable
class ChangeTracker(Protocol):
    """
    Интерфейс источника изменённых диапазонов (CBT). Возвращает список [ (offset, length), ... ].
    Диапазоны могут пересекаться — агрегируем внутри.
    """
    def changed_ranges(self, since_snapshot: "SnapshotManifest") -> List[Tuple[int, int]]: ...


# =================
# Исключения/ошибки
# =================

class SnapshotError(Exception):
    pass


class IntegrityError(SnapshotError):
    pass


class LockError(SnapshotError):
    pass


# ==============
# Манифест/типы
# ==============

@dataclass(frozen=True)
class ChunkRef:
    """
    Описание чанка в снапшоте:
    - hash: SHA256 hex содержимого чанка;
    - length: размер чанка в байтах;
    - offset: смещение в pack-файле, если source == "self"; иначе None;
    - source: "self" (в этом снапшоте данные) или "parent" (повторно используется чанк предка).
    """
    hash: str
    length: int
    offset: Optional[int]
    source: str  # "self" | "parent"


@dataclass(frozen=True)
class SnapshotManifest:
    version: str
    snapshot_id: str
    vm_id: str
    created_at: str
    size_bytes: int
    chunk_size: int
    parent_id: Optional[str]
    chunks: Tuple[ChunkRef, ...]
    sha256_of_manifest: str
    hmac_of_manifest: Optional[str] = None

    def to_json_bytes(self) -> bytes:
        # Стабильный сериализатор: сортировка ключей + без пробелов
        payload = {
            "version": self.version,
            "snapshot_id": self.snapshot_id,
            "vm_id": self.vm_id,
            "created_at": self.created_at,
            "size_bytes": self.size_bytes,
            "chunk_size": self.chunk_size,
            "parent_id": self.parent_id,
            "chunks": [c.__dict__ for c in self.chunks],
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ========================
# Вспомогательные утилиты
# ========================

def _utcnow_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).replace(microsecond=0).isoformat()

def _sha256(data: Union[bytes, bytearray, memoryview]) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

def _compute_hmac(data: bytes, key: Optional[bytes]) -> Optional[str]:
    if not key:
        return None
    return hmac.new(key, data, hashlib.sha256).hexdigest()

def _fsync_file_and_dir(file_path: Path) -> None:
    with open(file_path, "rb", buffering=0) as f:
        os.fsync(f.fileno())
    os.fsync(os.open(str(file_path.parent), os.O_DIRECTORY))

def _atomic_write_bytes(path: Path, data: bytes, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".tmp.{uuid4().hex}")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    os.chmod(path, mode)
    _fsync_file_and_dir(path)

def _open_pack_for_write(path: Path) -> Tuple[io.BufferedWriter, gzip.GzipFile]:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = open(path, "wb")
    gz = gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=6, mtime=0)  # mtime=0 для воспроизводимости
    return raw, gz

def _open_pack_for_read(path: Path) -> gzip.GzipFile:
    raw = open(path, "rb")
    return gzip.GzipFile(fileobj=raw, mode="rb")

def _merge_ranges(ranges: List[Tuple[int, int]], size: int) -> List[Tuple[int, int]]:
    """Склеить и нормализовать диапазоны (offset, length)."""
    norm: List[Tuple[int, int]] = []
    for off, ln in ranges:
        if ln <= 0:
            continue
        start = max(0, off)
        end = min(size, off + ln)
        if end <= start:
            continue
        norm.append((start, end))
    if not norm:
        return []
    norm.sort()
    merged: List[Tuple[int, int]] = [norm[0]]
    for s, e in norm[1:]:
        ls, le = merged[-1]
        if s <= le:
            merged[-1] = (ls, max(le, e))
        else:
            merged.append((s, e))
    return [(s, e - s) for s, e in merged]

class _DirLock:
    """Простой лок каталога через O_EXCL. Кроссплатформенно без внешних зависимостей."""
    def __init__(self, dir_path: Path) -> None:
        self._file = dir_path / LOCK_FILENAME
        self._fd: Optional[int] = None

    def acquire(self, timeout: float = 30.0, poll: float = 0.05) -> None:
        deadline = time.time() + timeout
        while True:
            try:
                self._fd = os.open(str(self._file), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.write(self._fd, str(os.getpid()).encode("ascii"))
                return
            except FileExistsError:
                if time.time() > deadline:
                    raise LockError(f"lock file exists: {self._file}")
                time.sleep(poll)

    def release(self) -> None:
        try:
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None
            if self._file.exists():
                self._file.unlink(missing_ok=True)
        except Exception:
            # не бросаем наружу при release
            pass

    def __enter__(self) -> "_DirLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()


# =======================
# Файловый стор снапшотов
# =======================

class LocalSnapshotStore:
    """
    Локальное хранилище: на диске создаётся структура
      base_dir/
        <vm_id>/
          snapshots/<snapshot_id>/{ manifest.json, data.pack.gz }
    """
    def __init__(self, base_dir: Union[str, Path]) -> None:
        self.base = Path(base_dir).resolve()

    def vm_dir(self, vm_id: str) -> Path:
        return self.base / vm_id

    def snapshot_dir(self, vm_id: str, snapshot_id: str) -> Path:
        return self.vm_dir(vm_id) / "snapshots" / snapshot_id

    def manifest_path(self, vm_id: str, snapshot_id: str) -> Path:
        return self.snapshot_dir(vm_id, snapshot_id) / MANIFEST_FILENAME

    def pack_path(self, vm_id: str, snapshot_id: str) -> Path:
        return self.snapshot_dir(vm_id, snapshot_id) / PACK_FILENAME

    def list_snapshots(self, vm_id: str) -> List[str]:
        root = self.vm_dir(vm_id) / "snapshots"
        if not root.exists():
            return []
        return sorted([p.name for p in root.iterdir() if p.is_dir()])

    def read_manifest(self, vm_id: str, snapshot_id: str) -> SnapshotManifest:
        p = self.manifest_path(vm_id, snapshot_id)
        data = p.read_bytes()
        doc = json.loads(data.decode("utf-8"))
        chunks = tuple(ChunkRef(hash=c["hash"], length=int(c["length"]), offset=c.get("offset"), source=c["source"]) for c in doc["chunks"])
        manifest = SnapshotManifest(
            version=doc["version"],
            snapshot_id=doc["snapshot_id"],
            vm_id=doc["vm_id"],
            created_at=doc["created_at"],
            size_bytes=int(doc["size_bytes"]),
            chunk_size=int(doc["chunk_size"]),
            parent_id=doc.get("parent_id"),
            chunks=chunks,
            sha256_of_manifest=_sha256(json.dumps({
                "version": doc["version"],
                "snapshot_id": doc["snapshot_id"],
                "vm_id": doc["vm_id"],
                "created_at": doc["created_at"],
                "size_bytes": doc["size_bytes"],
                "chunk_size": doc["chunk_size"],
                "parent_id": doc.get("parent_id"),
                "chunks": [c for c in doc["chunks"]],
            }, sort_keys=True, separators=(",", ":")).encode("utf-8")),
            hmac_of_manifest=doc.get("hmac_of_manifest"),
        )
        return manifest

    def write_snapshot_atomic(self, vm_id: str, snapshot_id: str, manifest: SnapshotManifest, pack_builder: bytes) -> None:
        # Для совместимости pack_builder здесь bytes только для сигнатуры; фактически мы пишем pack заранее потоком.
        # Манифест — атомарно.
        snap_dir = self.snapshot_dir(vm_id, snapshot_id)
        snap_dir.mkdir(parents=True, exist_ok=True)
        manifest_bytes = manifest.to_json_bytes()
        payload = json.loads(manifest_bytes.decode("utf-8"))
        payload["sha256_of_manifest"] = _sha256(manifest_bytes)
        # HMAC
        hkey = os.environ.get(ENV_HMAC_KEY, "")
        hmac_hex = _compute_hmac(manifest_bytes, hkey.encode("utf-8") if hkey else None)
        if hmac_hex:
            payload["hmac_of_manifest"] = hmac_hex
        final_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        _atomic_write_bytes(snap_dir / MANIFEST_FILENAME, final_bytes)


# ===========================
# Читалки/писалки по файлам
# ===========================

class FileReader(BlockReader):
    def __init__(self, path: Union[str, Path]) -> None:
        self._p = Path(path)
        self._size = self._p.stat().st_size

    def size_bytes(self) -> int:
        return self._size

    def read_at(self, offset: int, length: int) -> bytes:
        if length <= 0:
            return b""
        with open(self._p, "rb") as f:
            f.seek(offset)
            return f.read(length)


class FileWriter(BlockWriter):
    def __init__(self, path: Union[str, Path]) -> None:
        self._p = Path(path)
        # Гарантируем размер файла
        self._p.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self._p, "r+b") if self._p.exists() else open(self._p, "w+b")

    def size_bytes(self) -> int:
        return self._p.stat().st_size

    def write_at(self, offset: int, data: bytes) -> None:
        self._fh.seek(offset)
        self._fh.write(data)

    def flush(self) -> None:
        self._fh.flush()
        os.fsync(self._fh.fileno())


# ===========================
# Движок снапшотов (Engine)
# ===========================

class SnapshotEngine:
    """
    Создание/восстановление снапшотов с дедупликацией по родителю и проверкой целостности.
    Формат:
      - manifest.json: метаданные + список чанков (self/parent)
      - data.pack.gz: поток с последовательной записью собственных чанков
    """
    def __init__(self, store: LocalSnapshotStore) -> None:
        self._store = store
        self._lock = threading.Lock()

    # -------- Создание снапшота --------
    def create_snapshot(
        self,
        vm_id: str,
        reader: BlockReader,
        parent_snapshot_id: Optional[str] = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        change_tracker: Optional[ChangeTracker] = None,
        snapshot_id: Optional[str] = None,
    ) -> SnapshotManifest:
        if chunk_size <= 0:
            raise SnapshotError("chunk_size must be > 0")
        size = reader.size_bytes()
        snapshot_id = snapshot_id or uuid4().hex

        vm_dir = self._store.vm_dir(vm_id)
        vm_dir.mkdir(parents=True, exist_ok=True)
        with _DirLock(vm_dir):
            parent_manifest = self._load_parent(vm_id, parent_snapshot_id) if parent_snapshot_id else None
            parent_index: Dict[str, ChunkRef] = {}
            if parent_manifest:
                # Индекс родителя по хешу для быстрых совпадений
                parent_index = {c.hash: c for c in parent_manifest.chunks}

            snap_dir = self._store.snapshot_dir(vm_id, snapshot_id)
            tmp_dir = snap_dir.with_name(snap_dir.name + f".tmp.{uuid4().hex}")
            tmp_dir.mkdir(parents=True, exist_ok=False)

            pack_path = tmp_dir / PACK_FILENAME
            raw_fh, gz_fh = _open_pack_for_write(pack_path)
            pack_offset = 0

            chunks: List[ChunkRef] = []

            try:
                # Если есть CBT — ограничим диапазоны; иначе читаем всё.
                ranges = [(0, size)]
                if change_tracker and parent_manifest:
                    ranges = _merge_ranges(change_tracker.changed_ranges(parent_manifest), size) or []

                if not ranges and parent_manifest:
                    # Ничего не изменилось — пустой data.pack, все чанки — как у родителя с ссылками на parent.
                    chunks = [ChunkRef(hash=c.hash, length=c.length, offset=None, source="parent") for c in parent_manifest.chunks]
                else:
                    # Идём по диапазонам/чанкам
                    for start, length in ranges or [(0, size)]:
                        end = start + length
                        pos = start
                        while pos < end:
                            ln = min(chunk_size, end - pos)
                            data = reader.read_at(pos, ln)
                            if len(data) != ln:
                                raise SnapshotError("short read from BlockReader")
                            digest = _sha256(data)

                            if parent_index and digest in parent_index and parent_index[digest].length == ln:
                                # дедупликация по родителю
                                chunks.append(ChunkRef(hash=digest, length=ln, offset=None, source="parent"))
                            else:
                                # записываем в pack
                                gz_fh.write(data)
                                chunks.append(ChunkRef(hash=digest, length=ln, offset=pack_offset, source="self"))
                                pack_offset += ln
                            pos += ln

                gz_fh.flush()
                raw_fh.flush()
                os.fsync(raw_fh.fileno())
                gz_fh.close()
                raw_fh.close()

                # Сформировать манифест и атомарно перенести tmp -> snapshots/<id>
                manifest = SnapshotManifest(
                    version=SNAPSHOT_VERSION,
                    snapshot_id=snapshot_id,
                    vm_id=vm_id,
                    created_at=_utcnow_iso(),
                    size_bytes=size,
                    chunk_size=chunk_size,
                    parent_id=parent_manifest.snapshot_id if parent_manifest else None,
                    chunks=tuple(chunks),
                    sha256_of_manifest="",  # будет заполнен в write_snapshot_atomic
                    hmac_of_manifest=None,
                )

                # Переносим временный каталог в целевой
                final_dir = self._store.snapshot_dir(vm_id, snapshot_id)
                final_dir.parent.mkdir(parents=True, exist_ok=True)
                # Сначала переместим pack
                final_pack = self._store.pack_path(vm_id, snapshot_id)
                final_pack.parent.mkdir(parents=True, exist_ok=True)
                os.replace(pack_path, final_pack)

                # Запишем манифест атомарно
                self._store.write_snapshot_atomic(vm_id, snapshot_id, manifest, b"")

                # Удалим tmp_dir (если пустой)
                try:
                    tmp_dir.rmdir()
                except OSError:
                    # Если остались файлы — подчистим рекурсивно
                    for p in tmp_dir.glob("**/*"):
                        try:
                            p.unlink()
                        except Exception:
                            pass
                    try:
                        tmp_dir.rmdir()
                    except Exception:
                        pass

                _logger.info("snapshot created vm_id=%s snapshot_id=%s size=%d chunks=%d", vm_id, snapshot_id, size, len(chunks))
                return self._store.read_manifest(vm_id, snapshot_id)
            finally:
                try:
                    gz_fh.close()
                except Exception:
                    pass
                try:
                    raw_fh.close()
                except Exception:
                    pass

    # -------- Восстановление --------
    def restore_snapshot(self, manifest: SnapshotManifest, writer: BlockWriter) -> None:
        if writer.size_bytes() < manifest.size_bytes:
            # расширим файл до нужного размера (best-effort)
            with open(getattr(writer, "_p", "/dev/null"), "ab") as _:
                pass  # pragma: no cover (для FileWriter это не обяз.)
        offset = 0
        for ch in manifest.chunks:
            pack_path, poff = self._resolve_chunk(manifest.vm_id, manifest.snapshot_id, ch)
            data = self._read_chunk_from_pack(pack_path, poff, ch.length)
            if _sha256(data) != ch.hash:
                raise IntegrityError("chunk hash mismatch during restore")
            writer.write_at(offset, data)
            offset += ch.length
        writer.flush()
        _logger.info("snapshot restored vm_id=%s snapshot_id=%s bytes=%d", manifest.vm_id, manifest.snapshot_id, manifest.size_bytes)

    # -------- Проверки/операции --------
    def verify_snapshot(self, manifest: SnapshotManifest) -> None:
        # Проверка HMAC (если настроен ключ)
        expected_hmac = manifest.hmac_of_manifest
        actual_bytes = manifest.to_json_bytes()
        key = os.environ.get(ENV_HMAC_KEY, "")
        actual_hmac = _compute_hmac(actual_bytes, key.encode("utf-8") if key else None)
        if expected_hmac and (actual_hmac != expected_hmac):
            raise IntegrityError("manifest HMAC verification failed")

        # Проверка, что все self-чанки доступны
        pack_path = self._store.pack_path(manifest.vm_id, manifest.snapshot_id)
        if not pack_path.exists():
            # допустимо, если все чанки "parent" (инкремент без изменений)
            if any(c.source == "self" for c in manifest.chunks):
                raise SnapshotError("pack file missing for snapshot with self chunks")

        # Тестово читаем первые байты из каждого self-чанка
        if pack_path.exists():
            with _open_pack_for_read(pack_path) as gz:
                # ничего кроме существования файла гарантировать нельзя; детальная проверка — в restore
                pass

    def delete_snapshot(self, vm_id: str, snapshot_id: str) -> None:
        snap_dir = self._store.snapshot_dir(vm_id, snapshot_id)
        with _DirLock(self._store.vm_dir(vm_id)):
            # запрещаем удалять, если на него ссылаются дети (простая проверка)
            for s in self._store.list_snapshots(vm_id):
                if s == snapshot_id:
                    continue
                man = self._store.read_manifest(vm_id, s)
                if man.parent_id == snapshot_id:
                    raise SnapshotError(f"cannot delete: snapshot {snapshot_id} has child {s}")
            # удаляем файлы
            for p in [self._store.pack_path(vm_id, snapshot_id), self._store.manifest_path(vm_id, snapshot_id)]:
                try:
                    p.unlink(missing_ok=True)
                except Exception:
                    pass
            try:
                snap_dir.rmdir()
            except Exception:
                pass
            _logger.info("snapshot deleted vm_id=%s snapshot_id=%s", vm_id, snapshot_id)

    def list_snapshots(self, vm_id: str) -> List[SnapshotManifest]:
        ids = self._store.list_snapshots(vm_id)
        return [self._store.read_manifest(vm_id, sid) for sid in ids]

    # -------- Вспомогательные --------
    def _load_parent(self, vm_id: str, parent_id: Optional[str]) -> Optional[SnapshotManifest]:
        if not parent_id:
            return None
        return self._store.read_manifest(vm_id, parent_id)

    def _resolve_chunk(self, vm_id: str, snapshot_id: str, ch: ChunkRef) -> Tuple[Path, int]:
        """
        Найти источник чанка и вернуть (путь к pack, смещение).
        Рекурсивно поднимается к предкам, если требуется.
        """
        current_id = snapshot_id
        current_ch = ch
        while True:
            man = self._store.read_manifest(vm_id, current_id)
            if current_ch.source == "self":
                poff = current_ch.offset
                if poff is None:
                    raise SnapshotError("self chunk without offset")
                return self._store.pack_path(vm_id, current_id), poff
            if current_ch.source == "parent":
                pid = man.parent_id
                if not pid:
                    raise SnapshotError("chunk refers to parent but parent is missing")
                parent_manifest = self._store.read_manifest(vm_id, pid)
                # Ищем чанк по хешу в родителе
                found = next((c for c in parent_manifest.chunks if c.hash == current_ch.hash and c.length == current_ch.length), None)
                if not found:
                    raise SnapshotError("parent does not contain required chunk")
                current_id = pid
                current_ch = found
                continue
            raise SnapshotError(f"unknown chunk source: {current_ch.source}")

    @staticmethod
    def _read_chunk_from_pack(pack_path: Path, offset: int, length: int) -> bytes:
        with _open_pack_for_read(pack_path) as gz:
            # Последовательный формат gzip не поддерживает случайные seek,
            # поэтому читаем поток до нужной позиции. Для больших оффсетов это неэффективно,
            # но формат выбран из-за stdlib. В проде можно перейти на zstd + индекс.
            read = 0
            out = bytearray()
            buf_size = 1024 * 1024
            while read < offset + length:
                chunk = gz.read(min(buf_size, offset + length - read))
                if not chunk:
                    break
                # копим только нужный диапазон
                new_read = read + len(chunk)
                start = max(0, offset - read)
                end = min(len(chunk), offset + length - read)
                if start < end:
                    out.extend(chunk[start:end])
                read = new_read
            if len(out) != length:
                raise SnapshotError("failed to read required bytes from pack")
            return bytes(out)


# ============================
# Пример использования (docs)
# ============================

"""
Пример (файловые бэкенды):

from avm_core.engine.snapshot import (
    LocalSnapshotStore, SnapshotEngine, FileReader, FileWriter
)

store = LocalSnapshotStore("/var/lib/avm/snapshots")
engine = SnapshotEngine(store)

# 1) Создать полный снапшот
manifest = engine.create_snapshot(
    vm_id="vm-123",
    reader=FileReader("/var/lib/libvirt/images/vm-123.qcow2.raw"),
)

# 2) Создать инкрементальный снапшот относительно предыдущего
manifest2 = engine.create_snapshot(
    vm_id="vm-123",
    reader=FileReader("/var/lib/libvirt/images/vm-123.qcow2.raw"),
    parent_snapshot_id=manifest.snapshot_id,
    change_tracker=None,  # или ваш адаптер CBT
)

# 3) Проверить и восстановить
engine.verify_snapshot(manifest2)
engine.restore_snapshot(
    manifest2,
    writer=FileWriter("/restore/target.raw"),
)
"""

__all__ = [
    "BlockReader",
    "BlockWriter",
    "ChangeTracker",
    "SnapshotManifest",
    "ChunkRef",
    "LocalSnapshotStore",
    "FileReader",
    "FileWriter",
    "SnapshotEngine",
    "SnapshotError",
    "IntegrityError",
    "LockError",
    "SNAPSHOT_VERSION",
    "DEFAULT_CHUNK_SIZE",
]
