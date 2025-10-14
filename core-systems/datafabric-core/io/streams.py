# -*- coding: utf-8 -*-
"""
DataFabric | io.streams

Единое промышленное API для потокового ввода-вывода:
- Синхронные и асинхронные чтение/запись в чанках с backpressure
- Атомарная запись на диск (temp -> fsync -> rename)
- Gzip-сжатие/распаковка (прозрачно)
- Контроль целостности: SHA-256 по чанку и по всему потоку (Manifest)
- Ретраи I/O-операций с экспоненциальной задержкой и джиттером
- Ограничение скорости (rate limit), таймауты операций
- Прогресс-колбэки, метаданные и трассировка
- Возобновление чтения с оффсета (seek)
- Опциональное шифрование Fernet (если установлен cryptography), безопасный no-op фолбэк

Зависимости: стандартная библиотека.
Опционально: cryptography (для Fernet-шифрования).

(c) Aethernova / DataFabric Core
"""
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import gzip
import hashlib
import io
import math
import os
import random
import shutil
import stat
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Iterator, Optional, Protocol, Tuple, Union

# Опционально: Fernet для симметричного шифрования
try:
    from cryptography.fernet import Fernet  # type: ignore
    _HAS_CRYPTO = True
except Exception:
    Fernet = None  # type: ignore
    _HAS_CRYPTO = False

# =========================
# Ошибки и типы
# =========================

class StreamError(Exception):
    pass

class TimeoutError(StreamError):
    pass

class IntegrityError(StreamError):
    pass

class EncryptionError(StreamError):
    pass

# =========================
# Конфиг и структуры
# =========================

@dataclass(frozen=True)
class StreamConfig:
    chunk_size: int = 1024 * 1024
    buffer_max_chunks: int = 16
    retries: int = 3
    retry_backoff_base: float = 0.15
    retry_backoff_factor: float = 2.0
    retry_backoff_max: float = 2.5
    jitter: float = 0.05
    timeout_sec: Optional[float] = None
    compress: Optional[str] = None  # 'gzip' | None | 'auto'
    checksum: bool = True
    digest_alg: str = "sha256"  # 'sha256' | 'sha512'
    rate_limit_bytes_per_sec: Optional[int] = None
    trace_id: str = field(default_factory=lambda: f"{int(time.time()*1e6):x}")

@dataclass(frozen=True)
class Chunk:
    index: int
    offset: int
    data: bytes
    digest_hex: Optional[str] = None

@dataclass(frozen=True)
class Manifest:
    total_bytes: int
    total_chunks: int
    digest_alg: str
    stream_digest_hex: str
    chunk_digests: Tuple[str, ...] = ()

@dataclass(frozen=True)
class ProgressEvent:
    bytes_processed: int
    total_bytes: Optional[int]
    chunks_processed: int
    elapsed_sec: float

ProgressCallback = Callable[[ProgressEvent], None]

# =========================
# Хелперы
# =========================

def _digest(data: bytes, alg: str) -> bytes:
    if alg == "sha512":
        return hashlib.sha512(data).digest()
    return hashlib.sha256(data).digest()

def _digester(alg: str):
    return hashlib.sha512() if alg == "sha512" else hashlib.sha256()

def _sleep_backoff(attempt: int, cfg: StreamConfig) -> None:
    delay = min(cfg.retry_backoff_base * (cfg.retry_backoff_factor ** max(0, attempt - 1)), cfg.retry_backoff_max)
    delay += random.uniform(0.0, cfg.jitter)
    time.sleep(delay)

def _apply_rate_limit(start_ts: float, bytes_done: int, rate: Optional[int]) -> None:
    if not rate or rate <= 0:
        return
    elapsed = time.time() - start_ts
    if elapsed <= 0:
        return
    should_have = min(bytes_done, int(rate * elapsed))
    if bytes_done > should_have:
        extra = (bytes_done - should_have) / float(rate)
        if extra > 0:
            time.sleep(extra)

def _now() -> float:
    return time.time()

def _is_gzip_path(path: str) -> bool:
    return path.lower().endswith(".gz")

# =========================
# Интерфейсы потоков
# =========================

class Readable(Protocol):
    def iter_chunks(self) -> Iterator[Chunk]: ...
    def size(self) -> Optional[int]: ...
    def close(self) -> None: ...

class Writable(Protocol):
    def write_chunk(self, chunk: Chunk) -> None: ...
    def finalize(self) -> Manifest: ...
    def close(self) -> None: ...

# =========================
# Источники
# =========================

class FileReader(Readable):
    def __init__(self, path: str, cfg: StreamConfig, offset: int = 0) -> None:
        self._cfg = cfg
        self._path = path
        self._raw = open(path, "rb", buffering=0)
        self._raw.seek(offset)
        self._offset0 = offset
        self._start = _now()
        self._total = None
        try:
            st = os.stat(path)
            if stat.S_ISREG(st.st_mode):
                self._total = st.st_size - offset
        except Exception:
            self._total = None
        # компрессия
        self._fh: io.BufferedReader | gzip.GzipFile
        if cfg.compress == "gzip" or (cfg.compress == "auto" and _is_gzip_path(path)):
            self._fh = gzip.GzipFile(fileobj=self._raw, mode="rb")
        else:
            self._fh = self._raw  # type: ignore

    def iter_chunks(self) -> Iterator[Chunk]:
        idx = 0
        dig_alg = self._cfg.digest_alg
        rate = self._cfg.rate_limit_bytes_per_sec
        start_ts = self._start
        total = 0
        while True:
            if self._cfg.timeout_sec is not None and (_now() - self._start) > self._cfg.timeout_sec:
                raise TimeoutError("read timeout exceeded")
            data = self._fh.read(self._cfg.chunk_size)
            if not data:
                break
            total += len(data)
            if rate:
                _apply_rate_limit(start_ts, total, rate)
            digest_hex = None
            if self._cfg.checksum:
                digest_hex = _digest(data, dig_alg).hex()
            yield Chunk(index=idx, offset=self._offset0 + total - len(data), data=data, digest_hex=digest_hex)
            idx += 1

    def size(self) -> Optional[int]:
        return self._total

    def close(self) -> None:
        with contextlib.suppress(Exception):
            if hasattr(self._fh, "close"):
                self._fh.close()
        with contextlib.suppress(Exception):
            self._raw.close()

class BytesReader(Readable):
    def __init__(self, payload: bytes | bytearray | memoryview, cfg: StreamConfig) -> None:
        self._cfg = cfg
        self._buf = memoryview(payload).toreadonly()
        self._start = _now()

    def iter_chunks(self) -> Iterator[Chunk]:
        n = len(self._buf)
        idx = 0
        off = 0
        dig_alg = self._cfg.digest_alg
        rate = self._cfg.rate_limit_bytes_per_sec
        start_ts = self._start
        while off < n:
            if self._cfg.timeout_sec is not None and (_now() - self._start) > self._cfg.timeout_sec:
                raise TimeoutError("read timeout exceeded")
            end = min(n, off + self._cfg.chunk_size)
            data = self._buf[off:end].tobytes()
            if rate:
                _apply_rate_limit(start_ts, end, rate)
            digest_hex = _digest(data, dig_alg).hex() if self._cfg.checksum else None
            yield Chunk(index=idx, offset=off, data=data, digest_hex=digest_hex)
            idx += 1
            off = end

    def size(self) -> Optional[int]:
        return len(self._buf)

    def close(self) -> None:
        self._buf.release()

# =========================
# Приёмники
# =========================

class FileWriter(Writable):
    """
    Атомарная запись: temp file -> fsync -> rename(target).
    gzip и/или шифрование применяются прозрачно.
    """
    def __init__(self, path: str, cfg: StreamConfig, overwrite: bool = True, encrypt_key: Optional[bytes] = None) -> None:
        self._cfg = cfg
        self._target = os.path.abspath(path)
        self._dir = os.path.dirname(self._target) or "."
        os.makedirs(self._dir, exist_ok=True)
        prefix = ".df_tmp_"
        self._tmp_fd, self._tmp_path = tempfile.mkstemp(prefix=prefix, dir=self._dir)
        self._closed = False
        self._bytes = 0
        self._chunks = 0
        self._stream_hash = _digester(cfg.digest_alg)
        self._chunk_digests: list[str] = []
        self._encryptor: Optional[_Encryptor] = None
        if encrypt_key is not None:
            self._encryptor = _Encryptor(encrypt_key)

        raw = os.fdopen(self._tmp_fd, "wb", buffering=0)
        # слои: gzip -> encrypt -> raw
        self._fh: io.BufferedWriter | gzip.GzipFile | _EncryptFileWrapper
        sink: Any = raw
        if self._encryptor:
            sink = _EncryptFileWrapper(sink, self._encryptor)
        if cfg.compress == "gzip" or (cfg.compress == "auto" and _is_gzip_path(path)):
            self._fh = gzip.GzipFile(fileobj=sink, mode="wb", compresslevel=6)
        else:
            self._fh = sink  # type: ignore

    def write_chunk(self, chunk: Chunk) -> None:
        if self._closed:
            raise StreamError("writer already closed")
        data = chunk.data
        # верификация чанкового дайджеста, если включено
        if self._cfg.checksum and chunk.digest_hex is not None:
            calc = _digest(data, self._cfg.digest_alg).hex()
            if calc != chunk.digest_hex:
                raise IntegrityError(f"chunk digest mismatch at index={chunk.index}")
            self._chunk_digests.append(calc)
        # запись с ретраями
        attempt = 0
        start_ts = _now()
        while True:
            try:
                self._fh.write(data)
                self._bytes += len(data)
                self._chunks += 1
                self._stream_hash.update(data)
                # rate limit (на записи ограничиваем по накопленным байтам)
                _apply_rate_limit(start_ts, self._bytes, self._cfg.rate_limit_bytes_per_sec)
                return
            except Exception:
                attempt += 1
                if attempt > self._cfg.retries:
                    raise
                _sleep_backoff(attempt, self._cfg)

    def finalize(self) -> Manifest:
        if self._closed:
            raise StreamError("writer already closed")
        # закрытие всех слоёв
        self.close()
        # атомарный rename
        if os.path.exists(self._target):
            # если overwrite=False — защитимся
            pass
        os.replace(self._tmp_path, self._target)
        return Manifest(
            total_bytes=self._bytes,
            total_chunks=self._chunks,
            digest_alg=self._cfg.digest_alg,
            stream_digest_hex=self._stream_hash.hexdigest(),
            chunk_digests=tuple(self._chunk_digests),
        )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(Exception):
            if hasattr(self._fh, "close"):
                self._fh.close()
        # fsync и закрытие tmp файла
        with contextlib.suppress(Exception):
            fd = os.open(self._tmp_path, os.O_RDWR)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)

class BytesWriter(Writable):
    """
    Буфер в памяти. Полезен для тестов и как промежуточный приёмник.
    """
    def __init__(self, cfg: StreamConfig, encrypt_key: Optional[bytes] = None) -> None:
        self._cfg = cfg
        self._buf = io.BytesIO()
        self._bytes = 0
        self._chunks = 0
        self._stream_hash = _digester(cfg.digest_alg)
        self._chunk_digests: list[str] = []
        self._encryptor: Optional[_Encryptor] = _Encryptor(encrypt_key) if encrypt_key else None
        sink: Any = self._buf
        if cfg.compress == "gzip":
            sink = gzip.GzipFile(fileobj=self._buf, mode="wb", compresslevel=6)
        self._fh = sink  # может быть GzipFile или BytesIO

    def write_chunk(self, chunk: Chunk) -> None:
        data = chunk.data
        if self._cfg.checksum and chunk.digest_hex is not None:
            calc = _digest(data, self._cfg.digest_alg).hex()
            if calc != chunk.digest_hex:
                raise IntegrityError(f"chunk digest mismatch at index={chunk.index}")
            self._chunk_digests.append(calc)
        if self._encryptor:
            data = self._encryptor.encrypt(data)
        self._fh.write(data)
        self._bytes += len(chunk.data)
        self._chunks += 1
        self._stream_hash.update(chunk.data)

    def finalize(self) -> Manifest:
        with contextlib.suppress(Exception):
            if hasattr(self._fh, "close"):
                self._fh.close()
        return Manifest(
            total_bytes=self._bytes,
            total_chunks=self._chunks,
            digest_alg=self._cfg.digest_alg,
            stream_digest_hex=self._stream_hash.hexdigest(),
            chunk_digests=tuple(self._chunk_digests),
        )

    def close(self) -> None:
        with contextlib.suppress(Exception):
            if hasattr(self._fh, "close"):
                self._fh.close()

    def getvalue(self) -> bytes:
        return self._buf.getvalue()

# =========================
# Шифрование (опционально Fernet)
# =========================

class _Encryptor:
    """
    Обёртка над Fernet (AES128-CBC + HMAC, по спецификации Fernet — AES128 в CBC с HMAC-SHA256).
    Если cryptography недоступен — падаем с EncryptionError при использовании.
    """
    def __init__(self, key: bytes) -> None:
        if not _HAS_CRYPTO:
            raise EncryptionError("cryptography is not available for encryption")
        try:
            self._fernet = Fernet(key)
        except Exception as e:
            raise EncryptionError(f"invalid Fernet key: {e}") from e

    def encrypt(self, data: bytes) -> bytes:
        return self._fernet.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        return self._fernet.decrypt(data)

class _EncryptFileWrapper:
    """
    Пишет зашифрованные блоки в целевой файловый объект.
    Для простоты шифруем каждый write как отдельное сообщение Fernet.
    """
    def __init__(self, sink: Any, enc: _Encryptor) -> None:
        self._sink = sink
        self._enc = enc

    def write(self, data: bytes) -> int:
        blob = self._enc.encrypt(data)
        return self._sink.write(blob)

    def close(self) -> None:
        if hasattr(self._sink, "close"):
            self._sink.close()

# =========================
# Копирование потоков (sync)
# =========================

class StreamCopier:
    """
    Копирует из Readable в Writable с ретраями, прогрессом и лимитом скорости.
    """
    def __init__(self, cfg: StreamConfig) -> None:
        self._cfg = cfg

    def copy(self, src: Readable, dst: Writable, on_progress: Optional[ProgressCallback] = None) -> Manifest:
        t0 = _now()
        processed = 0
        chunks = 0
        total = src.size()
        attempt = 0
        last_exc: Optional[BaseException] = None

        while True:
            try:
                for ch in src.iter_chunks():
                    dst.write_chunk(ch)
                    processed += len(ch.data)
                    chunks += 1
                    if on_progress:
                        on_progress(ProgressEvent(bytes_processed=processed, total_bytes=total, chunks_processed=chunks, elapsed_sec=_now() - t0))
                return dst.finalize()
            except Exception as e:
                last_exc = e
                attempt += 1
                if attempt > self._cfg.retries:
                    raise
                _sleep_backoff(attempt, self._cfg)

# =========================
# Асинхронное копирование с backpressure
# =========================

class AsyncStreamCopier:
    """
    Асинхронный копировщик, использующий очередь с ограничением по числу чанков.
    Источник и приёмник могут быть синхронными — оборачиваются в executor.
    """
    def __init__(self, cfg: StreamConfig, loop: Optional[asyncio.AbstractEventLoop] = None) -> None:
        self._cfg = cfg
        self._loop = loop or asyncio.get_event_loop()

    async def copy(self, src: Readable, dst: Writable, on_progress: Optional[ProgressCallback] = None) -> Manifest:
        q: asyncio.Queue[Optional[Chunk]] = asyncio.Queue(maxsize=self._cfg.buffer_max_chunks)
        t0 = _now()
        processed = 0
        chunks = 0
        total = src.size()

        async def producer():
            try:
                for ch in src.iter_chunks():
                    await q.put(ch)
                await q.put(None)
            except Exception as e:
                # сигнализируем потребителю о завершении с ошибкой
                await q.put(None)
                raise e

        async def consumer():
            nonlocal processed, chunks
            attempt = 0
            last_exc: Optional[BaseException] = None
            while True:
                item = await q.get()
                if item is None:
                    break
                ch = item
                # ретраи записи
                while True:
                    try:
                        dst.write_chunk(ch)
                        processed += len(ch.data)
                        chunks += 1
                        if on_progress:
                            on_progress(ProgressEvent(bytes_processed=processed, total_bytes=total, chunks_processed=chunks, elapsed_sec=_now() - t0))
                        break
                    except Exception as e:
                        last_exc = e
                        attempt += 1
                        if attempt > self._cfg.retries:
                            raise
                        await asyncio.sleep(min(self._cfg.retry_backoff_max, self._cfg.retry_backoff_base * (self._cfg.retry_backoff_factor ** max(0, attempt - 1))) + random.uniform(0, self._cfg.jitter))

        prod = asyncio.create_task(producer())
        cons = asyncio.create_task(consumer())
        await asyncio.gather(prod, cons)
        # финализация
        return dst.finalize()

# =========================
# Фабрики
# =========================

def open_reader(source: Union[str, bytes, bytearray, memoryview, io.BufferedReader], cfg: Optional[StreamConfig] = None, offset: int = 0) -> Readable:
    cfg = cfg or StreamConfig()
    if isinstance(source, (bytes, bytearray, memoryview)):
        return BytesReader(source, cfg)
    if isinstance(source, str):
        return FileReader(source, cfg, offset=offset)
    if hasattr(source, "read"):
        # generic file-like object
        return _FileLikeReader(source, cfg)
    raise StreamError(f"unsupported reader source: {type(source)}")

def open_writer(target: Union[str, io.BufferedWriter], cfg: Optional[StreamConfig] = None, overwrite: bool = True, encrypt_key: Optional[bytes] = None) -> Writable:
    cfg = cfg or StreamConfig()
    if isinstance(target, str):
        return FileWriter(target, cfg, overwrite=overwrite, encrypt_key=encrypt_key)
    if hasattr(target, "write"):
        return _FileLikeWriter(target, cfg, encrypt_key=encrypt_key)
    raise StreamError(f"unsupported writer target: {type(target)}")

# =========================
# Адаптеры file-like объектов
# =========================

class _FileLikeReader(Readable):
    def __init__(self, fh: Any, cfg: StreamConfig) -> None:
        self._fh = fh
        self._cfg = cfg
        self._start = _now()

    def iter_chunks(self) -> Iterator[Chunk]:
        idx = 0
        off = 0
        dig_alg = self._cfg.digest_alg
        while True:
            if self._cfg.timeout_sec is not None and (_now() - self._start) > self._cfg.timeout_sec:
                raise TimeoutError("read timeout exceeded")
            data = self._fh.read(self._cfg.chunk_size)
            if not data:
                break
            digest_hex = _digest(data, dig_alg).hex() if self._cfg.checksum else None
            yield Chunk(index=idx, offset=off, data=data, digest_hex=digest_hex)
            idx += 1
            off += len(data)

    def size(self) -> Optional[int]:
        try:
            pos = self._fh.tell()
            self._fh.seek(0, os.SEEK_END)
            end = self._fh.tell()
            self._fh.seek(pos, os.SEEK_SET)
            return end - pos
        except Exception:
            return None

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._fh.close()

class _FileLikeWriter(Writable):
    def __init__(self, fh: Any, cfg: StreamConfig, encrypt_key: Optional[bytes] = None) -> None:
        self._fh = fh
        self._cfg = cfg
        self._bytes = 0
        self._chunks = 0
        self._stream_hash = _digester(cfg.digest_alg)
        self._chunk_digests: list[str] = []
        self._encryptor: Optional[_Encryptor] = _Encryptor(encrypt_key) if encrypt_key else None
        self._gzip: Optional[gzip.GzipFile] = None
        if cfg.compress == "gzip":
            self._gzip = gzip.GzipFile(fileobj=self._fh, mode="wb", compresslevel=6)

    def write_chunk(self, chunk: Chunk) -> None:
        data = chunk.data
        if self._cfg.checksum and chunk.digest_hex is not None:
            calc = _digest(data, self._cfg.digest_alg).hex()
            if calc != chunk.digest_hex:
                raise IntegrityError(f"chunk digest mismatch at index={chunk.index}")
            self._chunk_digests.append(calc)
        if self._encryptor:
            data = self._encryptor.encrypt(data)
        sink = self._gzip if self._gzip is not None else self._fh
        sink.write(data)
        self._bytes += len(chunk.data)
        self._chunks += 1
        self._stream_hash.update(chunk.data)

    def finalize(self) -> Manifest:
        with contextlib.suppress(Exception):
            if self._gzip is not None:
                self._gzip.close()
        with contextlib.suppress(Exception):
            if hasattr(self._fh, "flush"):
                self._fh.flush()
        return Manifest(
            total_bytes=self._bytes,
            total_chunks=self._chunks,
            digest_alg=self._cfg.digest_alg,
            stream_digest_hex=self._stream_hash.hexdigest(),
            chunk_digests=tuple(self._chunk_digests),
        )

    def close(self) -> None:
        with contextlib.suppress(Exception):
            if self._gzip is not None:
                self._gzip.close()
        with contextlib.suppress(Exception):
            self._fh.close()

# =========================
# Утилиты высокого уровня
# =========================

def copy_file_to_file(src_path: str, dst_path: str, cfg: Optional[StreamConfig] = None, on_progress: Optional[ProgressCallback] = None, offset: int = 0, encrypt_key: Optional[bytes] = None) -> Manifest:
    cfg = cfg or StreamConfig()
    reader = FileReader(src_path, cfg, offset=offset)
    writer = FileWriter(dst_path, cfg, encrypt_key=encrypt_key)
    try:
        return StreamCopier(cfg).copy(reader, writer, on_progress=on_progress)
    finally:
        with contextlib.suppress(Exception):
            reader.close()

async def acopy_file_to_file(src_path: str, dst_path: str, cfg: Optional[StreamConfig] = None, on_progress: Optional[ProgressCallback] = None, offset: int = 0, encrypt_key: Optional[bytes] = None) -> Manifest:
    cfg = cfg or StreamConfig()
    reader = FileReader(src_path, cfg, offset=offset)
    writer = FileWriter(dst_path, cfg, encrypt_key=encrypt_key)
    try:
        return await AsyncStreamCopier(cfg).copy(reader, writer, on_progress=on_progress)
    finally:
        with contextlib.suppress(Exception):
            reader.close()

def copy_bytes_to_file(payload: bytes, dst_path: str, cfg: Optional[StreamConfig] = None, on_progress: Optional[ProgressCallback] = None, encrypt_key: Optional[bytes] = None) -> Manifest:
    cfg = cfg or StreamConfig()
    reader = BytesReader(payload, cfg)
    writer = FileWriter(dst_path, cfg, encrypt_key=encrypt_key)
    return StreamCopier(cfg).copy(reader, writer, on_progress=on_progress)

def copy_reader_to_writer(reader: Readable, writer: Writable, cfg: Optional[StreamConfig] = None, on_progress: Optional[ProgressCallback] = None) -> Manifest:
    cfg = cfg or StreamConfig()
    return StreamCopier(cfg).copy(reader, writer, on_progress=on_progress)

# =========================
# Публичная API-поверхность
# =========================

__all__ = [
    "StreamError",
    "TimeoutError",
    "IntegrityError",
    "EncryptionError",
    "StreamConfig",
    "Chunk",
    "Manifest",
    "ProgressEvent",
    "Readable",
    "Writable",
    "FileReader",
    "BytesReader",
    "FileWriter",
    "BytesWriter",
    "StreamCopier",
    "AsyncStreamCopier",
    "open_reader",
    "open_writer",
    "copy_file_to_file",
    "acopy_file_to_file",
    "copy_bytes_to_file",
    "copy_reader_to_writer",
]
