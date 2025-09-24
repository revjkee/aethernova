# SPDX-License-Identifier: Apache-2.0
"""
AVM Core :: Backup Engine
Промышленный потоковый бэкап VM со снапшотами, ретенцией и проверкой целостности.

Возможности:
- Провайдеры снапшотов: командный (stdout), файловый (готовый образ), плагинный.
- Потоковая компрессия: zstd (если установлен), иначе gzip; можно выключить.
- Опциональное шифрование AES-256-GCM (если установлен cryptography).
- Хранилища: локальная ФС и S3 (если установлен boto3).
- Контроль целостности: SHA-256 (целевая) и опционально SHA-256 исходного потока.
- Идемпотентность: атомарная запись .part → rename, повторяемые операции.
- GFS-ретенция (Grandfather-Father-Son): hourly/daily/weekly/monthly.
- Асинхронная оркестрация и лимитирование скорости.
- Манифесты JSON с метаданными, ключами шифрования (только мета), картой чанков.

Секретов не содержит. Ключи и креды поставляются через окружение/секрет‑менеджер снаружи.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import datetime as dt
import gzip
import hashlib
import io
import json
import logging
import os
import pathlib
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import AsyncIterator, Callable, Dict, Iterable, List, Mapping, Optional, Protocol, Tuple, Union

# Опциональные зависимости
try:
    import zstandard as zstd  # type: ignore
    _HAS_ZSTD = True
except Exception:
    _HAS_ZSTD = False

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
    _HAS_CRYPTO = True
except Exception:
    _HAS_CRYPTO = False

try:
    import boto3  # type: ignore
    from botocore.config import Config as BotoConfig  # type: ignore
    _HAS_BOTO3 = True
except Exception:
    _HAS_BOTO3 = False


log = logging.getLogger(__name__)


# =========================
# Константы и утилиты
# =========================

DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024  # 8 MiB
MANIFEST_VERSION = 1


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def sha256_update(h: "hashlib._Hash", data: bytes) -> None:
    h.update(data)


def b64u(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# =========================
# Модели и протоколы
# =========================

class RetentionClass(str, Enum):
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


@dataclass(frozen=True)
class RetentionPolicy:
    hourly: int = 24
    daily: int = 7
    weekly: int = 4
    monthly: int = 12

    def classify(self, ts: dt.datetime) -> RetentionClass:
        # Простая эвристика: начало месяца/недели/дня/часа
        if ts.day == 1:
            return RetentionClass.MONTHLY
        if ts.weekday() == 6:  # воскресенье
            return RetentionClass.WEEKLY
        if ts.hour == 0:
            return RetentionClass.DAILY
        return RetentionClass.HOURLY

    def keep_count(self, cls: RetentionClass) -> int:
        return {
            RetentionClass.HOURLY: self.hourly,
            RetentionClass.DAILY: self.daily,
            RetentionClass.WEEKLY: self.weekly,
            RetentionClass.MONTHLY: self.monthly,
        }[cls]


@dataclass(frozen=True)
class VMTarget:
    vm_id: str
    name: str
    provider: str  # "command" | "file" | "plugin:<entrypoint>"
    snapshot_spec: Mapping[str, str]  # параметры для провайдера
    labels: Mapping[str, str] = dataclasses.field(default_factory=dict)


@dataclass
class BackupManifest:
    version: int
    vm: Mapping[str, str]
    created_at: str
    retention: str
    chunk_size: int
    chunks: int
    compressed: str  # "zstd" | "gzip" | "none"
    encrypted: str   # "aes256gcm" | "none"
    size_bytes: int
    sha256: str      # хэш зашифрованного потока (целевой)
    plain_sha256: Optional[str]
    storage_uri: str
    meta: Mapping[str, str] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), ensure_ascii=False, sort_keys=True, indent=2)


class SnapshotProvider(Protocol):
    async def open_stream(self, vm: VMTarget) -> AsyncIterator[bytes]:
        """
        Вернуть поток байтов снапшота VM (raw/qcow2/vmdk — не важно для стора).
        Обязательно завершайте итератор; провайдер отвечает за freeze/thaw, если нужно.
        """
        ...


class StorageBackend(Protocol):
    async def store(self, key: str, stream: AsyncIterator[bytes], *, metadata: Mapping[str, str]) -> Tuple[str, str, int]:
        """
        Сохранить поток под ключом key. Вернуть (uri, etag/sha, size_bytes).
        Реализация должна быть идемпотентной: запись во временный объект и атомарный commit/rename.
        """
        ...

    async def list_keys(self, prefix: str) -> List[str]:
        ...

    async def delete(self, key: str) -> None:
        ...


# =========================
# Провайдеры снапшотов
# =========================

class CommandSnapshotProvider:
    """
    Универсальный провайдер: запускает команду и читает снапшот из stdout.
    Пример: qemu-img convert -O raw /dev/vm-disks/vm1 -
    snapshot_spec:
      cmd: "/usr/bin/qemu-img"
      args: ["convert","-O","raw","/vm-disks/vm1","-"]
      cwd: "/"
      env: { LIBVIRT_DEFAULT_URI: "qemu:///system" }
    """
    def __init__(self, read_chunk: int = DEFAULT_CHUNK_SIZE) -> None:
        self._chunk = read_chunk

    async def open_stream(self, vm: VMTarget) -> AsyncIterator[bytes]:
        spec = vm.snapshot_spec
        cmd = [spec.get("cmd", "")] + list(spec.get("args", []))
        if not cmd[0]:
            raise ValueError("snapshot_spec.cmd is required for CommandSnapshotProvider")
        env = os.environ.copy()
        env.update(spec.get("env", {}))  # type: ignore[arg-type]
        cwd = spec.get("cwd", None)

        log.info("Snapshot command starting vm_id=%s cmd=%s", vm.vm_id, " ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env,
        )
        assert proc.stdout is not None
        try:
            while True:
                chunk = await proc.stdout.read(self._chunk)
                if not chunk:
                    break
                yield chunk
            rc = await proc.wait()
            if rc != 0:
                stderr = await proc.stderr.read() if proc.stderr else b""
                raise RuntimeError(f"Snapshot command failed rc={rc}: {stderr.decode('utf-8', 'ignore')}")
        finally:
            with contextlib.suppress(ProcessLookupError):
                if proc.returncode is None:
                    proc.terminate()


class FileSnapshotProvider:
    """
    Читает снапшот из файла (например, предварительно созданный снапшот LVM/ZFS).
    snapshot_spec: { path: "/var/backups/vm1.raw", remove_after: "false" }
    """
    def __init__(self, read_chunk: int = DEFAULT_CHUNK_SIZE) -> None:
        self._chunk = read_chunk

    async def open_stream(self, vm: VMTarget) -> AsyncIterator[bytes]:
        path = vm.snapshot_spec.get("path")
        if not path or not os.path.exists(path):
            raise FileNotFoundError(f"Snapshot path not found: {path}")
        log.info("Reading snapshot file vm_id=%s path=%s", vm.vm_id, path)
        f = await asyncio.to_thread(open, path, "rb", buffering=0)
        try:
            while True:
                chunk = await asyncio.to_thread(f.read, self._chunk)
                if not chunk:
                    break
                yield chunk
        finally:
            try:
                f.close()
            except Exception:
                pass
            if str(vm.snapshot_spec.get("remove_after", "")).lower() in ("1", "true", "yes"):
                with contextlib.suppress(Exception):
                    os.remove(path)


# =========================
# Сторы
# =========================

class FilesystemBackend:
    """
    Локальный стор в директории base_dir. Пишет во временный .part с fsync, затем rename.
    """
    def __init__(self, base_dir: Union[str, os.PathLike]) -> None:
        self._base = pathlib.Path(base_dir)
        self._base.mkdir(parents=True, exist_ok=True)

    async def store(self, key: str, stream: AsyncIterator[bytes], *, metadata: Mapping[str, str]) -> Tuple[str, str, int]:
        dest = self._base / key
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".part")
        h = hashlib.sha256()
        size = 0

        f = await asyncio.to_thread(open, tmp, "wb", buffering=0)
        try:
            # sidecar metadata json (write early; обновим size/hash в манифесте)
            meta_path = dest.with_suffix(dest.suffix + ".meta.json")
            await asyncio.to_thread(lambda: meta_path.parent.mkdir(parents=True, exist_ok=True))
            await asyncio.to_thread(lambda: meta_path.write_text(json.dumps(dict(metadata), ensure_ascii=False)))
            async for chunk in stream:
                await asyncio.to_thread(f.write, chunk)
                size += len(chunk)
                sha256_update(h, chunk)
            await asyncio.to_thread(f.flush)
            await asyncio.to_thread(os.fsync, f.fileno())
        finally:
            try:
                f.close()
            except Exception:
                pass

        await asyncio.to_thread(os.replace, tmp, dest)
        # Права только для владельца
        await asyncio.to_thread(os.chmod, dest, stat.S_IRUSR | stat.S_IWUSR)
        uri = dest.as_posix()
        return uri, h.hexdigest(), size

    async def list_keys(self, prefix: str) -> List[str]:
        base = (self._base / prefix).parent if prefix else self._base
        results: List[str] = []
        if not base.exists():
            return results
        for p in base.rglob("*"):
            if p.is_file():
                rel = p.relative_to(self._base).as_posix()
                if rel.startswith(prefix):
                    results.append(rel)
        results.sort()
        return results

    async def delete(self, key: str) -> None:
        path = self._base / key
        with contextlib.suppress(FileNotFoundError):
            await asyncio.to_thread(os.remove, path)
        meta = path.with_suffix(path.suffix + ".meta.json")
        with contextlib.suppress(FileNotFoundError):
            await asyncio.to_thread(os.remove, meta)


class S3Backend:
    """
    S3-совместимый стор (minio/AWS). Требует boto3.
    """
    def __init__(self, bucket: str, prefix: str = "", endpoint_url: Optional[str] = None, region: Optional[str] = None, extra: Optional[Mapping[str, str]] = None) -> None:
        if not _HAS_BOTO3:
            raise RuntimeError("boto3 is not installed")
        session = boto3.session.Session()
        cfg = BotoConfig(retries={"max_attempts": 5, "mode": "standard"}, signature_version="s3v4", region_name=region)
        self._s3 = session.client("s3", endpoint_url=endpoint_url, config=cfg)
        self._bucket = bucket
        self._prefix = (prefix.rstrip("/") + "/") if prefix and not prefix.endswith("/") else (prefix or "")

        # Создание бакета не выполняем автоматически в проде

        self._extra = dict(extra or {})

    async def store(self, key: str, stream: AsyncIterator[bytes], *, metadata: Mapping[str, str]) -> Tuple[str, str, int]:
        full_key = self._prefix + key
        # multipart загрузка вручную, чтобы не буферизовать целиком
        # Простая реализация с create_multipart_upload / upload_part / complete
        create = await asyncio.to_thread(self._s3.create_multipart_upload, Bucket=self._bucket, Key=full_key, Metadata=dict(metadata), **self._extra)
        upload_id = create["UploadId"]
        parts: List[Dict[str, Union[int, str]]] = []
        h = hashlib.sha256()
        size = 0
        part_number = 1

        try:
            buf = bytearray()
            async for chunk in stream:
                buf.extend(chunk)
                size += len(chunk)
                sha256_update(h, chunk)
                if len(buf) >= DEFAULT_CHUNK_SIZE:
                    etag = await asyncio.to_thread(self._upload_part, full_key, upload_id, part_number, bytes(buf))
                    parts.append({"ETag": etag, "PartNumber": part_number})
                    buf.clear()
                    part_number += 1
            if buf:
                etag = await asyncio.to_thread(self._upload_part, full_key, upload_id, part_number, bytes(buf))
                parts.append({"ETag": etag, "PartNumber": part_number})
            await asyncio.to_thread(self._s3.complete_multipart_upload, Bucket=self._bucket, Key=full_key, UploadId=upload_id, MultipartUpload={"Parts": parts})
        except Exception:
            with contextlib.suppress(Exception):
                await asyncio.to_thread(self._s3.abort_multipart_upload, Bucket=self._bucket, Key=full_key, UploadId=upload_id)
            raise

        uri = f"s3://{self._bucket}/{full_key}"
        return uri, h.hexdigest(), size

    def _upload_part(self, key: str, upload_id: str, part_number: int, data: bytes) -> str:
        resp = self._s3.upload_part(Bucket=self._bucket, Key=key, UploadId=upload_id, PartNumber=part_number, Body=data)
        return resp["ETag"].strip('"')

    async def list_keys(self, prefix: str) -> List[str]:
        full_pref = self._prefix + prefix
        token = None
        items: List[str] = []
        while True:
            resp = await asyncio.to_thread(self._s3.list_objects_v2, Bucket=self._bucket, Prefix=full_pref, ContinuationToken=token) if token else await asyncio.to_thread(self._s3.list_objects_v2, Bucket=self._bucket, Prefix=full_pref)
            for obj in resp.get("Contents", []):
                key = obj["Key"]
                if not key.startswith(self._prefix):
                    continue
                items.append(key[len(self._prefix):])
            if not resp.get("IsTruncated"):
                break
            token = resp.get("NextContinuationToken")
        items.sort()
        return items

    async def delete(self, key: str) -> None:
        full_key = self._prefix + key
        await asyncio.to_thread(self._s3.delete_object, Bucket=self._bucket, Key=full_key)


# =========================
# Пайплайн трансформаций
# =========================

class RateLimiter:
    """Простой токен-бакет по байтам/секунда."""
    def __init__(self, bytes_per_sec: Optional[int]) -> None:
        self.rate = bytes_per_sec or 0
        self._allowance = float(self.rate)
        self._last_check = time.monotonic()

    def throttle(self, nbytes: int) -> None:
        if self.rate <= 0:
            return
        now = time.monotonic()
        elapsed = now - self._last_check
        self._last_check = now
        self._allowance += elapsed * self.rate
        if self._allowance > self.rate:
            self._allowance = float(self.rate)
        if self._allowance < nbytes:
            sleep_time = (nbytes - self._allowance) / self.rate
            time.sleep(max(0.0, sleep_time))
            self._allowance = 0
        else:
            self._allowance -= nbytes


async def transform_stream(
    source: AsyncIterator[bytes],
    *,
    compress: str = "zstd",  # "zstd" | "gzip" | "none"
    encrypt_key: Optional[bytes] = None,  # 32 bytes for AES-256-GCM
    rate_limit_bps: Optional[int] = None,
) -> AsyncIterator[bytes]:
    """
    Потоковая компрессия и шифрование. Порядок: сначала компрессия, затем шифрование.
    """
    limiter = RateLimiter(rate_limit_bps)

    # Компрессор
    if compress == "zstd" and _HAS_ZSTD:
        cctx = zstd.ZstdCompressor(level=10).compressobj()
        def _comp(data: bytes) -> bytes:
            return cctx.compress(data)
        def _flush() -> bytes:
            return cctx.flush()
        comp_name = "zstd"
    elif compress == "gzip":
        z = gzip.compress
        def _comp(data: bytes) -> bytes:
            return z(data, compresslevel=6) if len(data) >= 32 * 1024 else gzip.compress(data, compresslevel=1)
        def _flush() -> bytes:
            return b""
        comp_name = "gzip"
    else:
        def _comp(data: bytes) -> bytes:
            return data
        def _flush() -> bytes:
            return b""
        comp_name = "none"

    # Шифратор — простой блочно‑пакетный режим поверх чанков (новый nonce на чанк)
    if encrypt_key and _HAS_CRYPTO:
        aead = AESGCM(encrypt_key)
        # фиксированный префикс nonce на сессию
        session_nonce_prefix = os.urandom(8)
        counter = 0

        def _enc(data: bytes) -> bytes:
            nonlocal counter
            # nonce: 8 байт префикса + 4 байта счетчика
            nonce = session_nonce_prefix + counter.to_bytes(4, "big")
            counter += 1
            return aead.encrypt(nonce, data, None)  # ciphertext|tag
        enc_name = "aes256gcm"
    else:
        def _enc(data: bytes) -> bytes:
            return data
        enc_name = "none"

    # Преамбула (мета-тег формата)
    header = json.dumps({
        "v": 1,
        "compress": comp_name,
        "encrypt": enc_name,
    }).encode("utf-8")
    header_line = b"#avm/backup:" + b64u(header).encode("ascii") + b"\n"
    yield header_line

    async for chunk in source:
        c = _comp(chunk)
        if c:
            e = _enc(c)
            limiter.throttle(len(e))
            yield e
    tail = _flush()
    if tail:
        e = _enc(tail)
        limiter.throttle(len(e))
        yield e


# =========================
# Оркестратор и ретенция
# =========================

@dataclass
class BackupOptions:
    storage_prefix: str = "backups"
    compress: str = "zstd"
    encrypt_key: Optional[bytes] = None  # 32 байта или None
    chunk_size: int = DEFAULT_CHUNK_SIZE
    rate_limit_bps: Optional[int] = None
    plain_hash: bool = False  # считать SHA-256 исходного потока (дорого)
    dry_run: bool = False


class BackupOrchestrator:
    def __init__(self, storage: StorageBackend, provider_map: Mapping[str, SnapshotProvider], retention: RetentionPolicy = RetentionPolicy()) -> None:
        self._storage = storage
        self._providers = dict(provider_map)
        self._retention = retention

    def _pick_provider(self, vm: VMTarget) -> SnapshotProvider:
        if vm.provider == "command":
            return self._providers.get("command") or CommandSnapshotProvider()
        if vm.provider == "file":
            return self._providers.get("file") or FileSnapshotProvider()
        if vm.provider.startswith("plugin:"):
            key = vm.provider.split(":", 1)[1]
            prov = self._providers.get(key)
            if not prov:
                raise KeyError(f"Plugin provider not registered: {key}")
            return prov
        raise ValueError(f"Unsupported provider: {vm.provider}")

    async def backup_vm(self, vm: VMTarget, opts: BackupOptions) -> BackupManifest:
        ts = utcnow()
        rcls = self._retention.classify(ts)
        ts_str = ts.strftime("%Y%m%dT%H%M%SZ")

        key_base = f"{opts.storage_prefix}/{vm.name}/{rcls.value}/{ts_str}"
        data_key = f"{key_base}.avm"
        manifest_key = f"{key_base}.manifest.json"

        if opts.dry_run:
            # Формируем пустой манифест без записи данных
            log.info("Dry-run backup vm_id=%s name=%s class=%s key=%s", vm.vm_id, vm.name, rcls.value, data_key)
            return BackupManifest(
                version=MANIFEST_VERSION,
                vm={"vm_id": vm.vm_id, "name": vm.name},
                created_at=ts.isoformat(),
                retention=rcls.value,
                chunk_size=opts.chunk_size,
                chunks=0,
                compressed=opts.compress,
                encrypted="aes256gcm" if (opts.encrypt_key and _HAS_CRYPTO) else "none",
                size_bytes=0,
                sha256="",
                plain_sha256=None,
                storage_uri=f"(dry-run):{data_key}",
                meta={"dry_run": "true"},
            )

        provider = self._pick_provider(vm)
        src_stream = provider.open_stream(vm)

        # plain hash (опционально)
        plain_hasher = hashlib.sha256() if opts.plain_hash else None

        async def _tap_plain(iter_src: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
            async for chunk in iter_src:
                if plain_hasher:
                    sha256_update(plain_hasher, chunk)
                yield chunk

        transformed = transform_stream(_tap_plain(src_stream), compress=opts.compress, encrypt_key=opts.encrypt_key, rate_limit_bps=opts.rate_limit_bps)

        # Запись в стор
        meta = {
            "vm_id": vm.vm_id,
            "vm_name": vm.name,
            "created_at": ts.isoformat(),
            "retention": rcls.value,
            "compress": opts.compress if _HAS_ZSTD or opts.compress != "zstd" else "gzip" if opts.compress == "zstd" else opts.compress,
            "encrypted": "aes256gcm" if (opts.encrypt_key and _HAS_CRYPTO) else "none",
            "labels": json.dumps(dict(vm.labels), ensure_ascii=False),
        }
        uri, digest, size = await self._storage.store(data_key, transformed, metadata=meta)

        manifest = BackupManifest(
            version=MANIFEST_VERSION,
            vm={"vm_id": vm.vm_id, "name": vm.name},
            created_at=ts.isoformat(),
            retention=rcls.value,
            chunk_size=opts.chunk_size,
            chunks=max(1, size // max(1, opts.chunk_size) + (1 if size % max(1, opts.chunk_size) else 0)),
            compressed=meta["compress"],
            encrypted=meta["encrypted"],
            size_bytes=size,
            sha256=digest,
            plain_sha256=plain_hasher.hexdigest() if plain_hasher else None,
            storage_uri=uri,
            meta={},
        )

        # Сохраняем манифест рядом
        man_uri, man_etag, _ = await self._storage.store(manifest_key, _iter_bytes(manifest.to_json().encode("utf-8")), metadata={"kind": "manifest", "data_key": data_key})
        log.info("Backup completed vm_id=%s uri=%s manifest=%s sha256=%s size=%d", vm.vm_id, uri, man_uri, digest, size)

        # Подрежем старые бэкапы по классу ретенции
        await self._apply_retention(vm.name, rcls)

        return manifest

    async def _apply_retention(self, vm_name: str, rcls: RetentionClass) -> None:
        prefix = f"backups/{vm_name}/{rcls.value}/"
        keys = await self._storage.list_keys(prefix)
        # Оставляем только манифесты для сортировки по времени
        manifests = sorted([k for k in keys if k.endswith(".manifest.json")])
        keep = self._retention.keep_count(rcls)
        excess = max(0, len(manifests) - keep)
        if excess <= 0:
            return
        to_delete = manifests[:excess]
        for mkey in to_delete:
            base = mkey[:-len(".manifest.json")]
            data_key = base + ".avm"
            with contextlib.suppress(Exception):
                await self._storage.delete(mkey)
            with contextlib.suppress(Exception):
                await self._storage.delete(data_key)
            log.info("Retention purge vm=%s class=%s key=%s", vm_name, rcls.value, base)


def _iter_bytes(b: bytes) -> AsyncIterator[bytes]:
    async def gen() -> AsyncIterator[bytes]:
        yield b
    return gen()


# =========================
# Пример сборки (DI-склейка)
# =========================

def build_orchestrator_fs(base_dir: Union[str, os.PathLike]) -> BackupOrchestrator:
    storage = FilesystemBackend(base_dir)
    providers: Dict[str, SnapshotProvider] = {
        "command": CommandSnapshotProvider(),
        "file": FileSnapshotProvider(),
    }
    return BackupOrchestrator(storage=storage, provider_map=providers)


def build_orchestrator_s3(bucket: str, prefix: str = "", endpoint_url: Optional[str] = None, region: Optional[str] = None, extra: Optional[Mapping[str, str]] = None) -> BackupOrchestrator:
    if not _HAS_BOTO3:
        raise RuntimeError("boto3 is not installed")
    storage = S3Backend(bucket=bucket, prefix=prefix, endpoint_url=endpoint_url, region=region, extra=extra)
    providers: Dict[str, SnapshotProvider] = {
        "command": CommandSnapshotProvider(),
        "file": FileSnapshotProvider(),
    }
    return BackupOrchestrator(storage=storage, provider_map=providers)


# =========================
# CLI (локальный запуск)
# =========================

async def _main(argv: List[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="AVM Core Backup")
    parser.add_argument("--vm-id", required=True)
    parser.add_argument("--vm-name", required=True)
    parser.add_argument("--provider", choices=["command", "file"], required=True)
    parser.add_argument("--spec", help='JSON снапшот-спека, например {"cmd": "...", "args": ["..."]} или {"path":"..."}', required=True)
    parser.add_argument("--fs-dir", help="Базовая директория для файлового стора")
    parser.add_argument("--s3-bucket")
    parser.add_argument("--s3-prefix", default="")
    parser.add_argument("--s3-endpoint")
    parser.add_argument("--s3-region")
    parser.add_argument("--compress", choices=["zstd", "gzip", "none"], default="zstd")
    parser.add_argument("--encrypt-key-hex", help="32‑байтовый ключ AES‑256‑GCM в hex (опц.)")
    parser.add_argument("--rate", type=int, help="Лимит скорости, байт/сек (опц.)")
    parser.add_argument("--plain-hash", action="store_true", help="Считать SHA‑256 исходного потока")
    parser.add_argument("--dry-run", action="store_true")

    args = parser.parse_args(argv)

    spec = json.loads(args.spec)
    vm = VMTarget(vm_id=args.vm_id, name=args.vm_name, provider=args.provider, snapshot_spec=spec)

    if args.fs_dir:
        orch = build_orchestrator_fs(args.fs_dir)
    elif args.s3_bucket:
        orch = build_orchestrator_s3(args.s3_bucket, prefix=args.s3_prefix, endpoint_url=args.s3_endpoint, region=args.s3_region)
    else:
        print("Нужно указать --fs-dir или --s3-bucket", file=sys.stderr)
        return 2

    key = bytes.fromhex(args.encrypt_key_hex) if args.encrypt_key_hex else None
    if key and len(key) != 32:
        print("Ключ AES‑256‑GCM должен быть 32 байта в hex", file=sys.stderr)
        return 2
    if key and not _HAS_CRYPTO:
        print("Библиотека cryptography не установлена — шифрование недоступно", file=sys.stderr)
        return 2

    opts = BackupOptions(compress=args.compress, encrypt_key=key, rate_limit_bps=args.rate, plain_hash=args.plain_hash, dry_run=args.dry_run)

    manifest = await orch.backup_vm(vm, opts)
    print(manifest.to_json())
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        rc = asyncio.run(_main(sys.argv[1:]))
    except KeyboardInterrupt:
        rc = 130
    sys.exit(rc)
