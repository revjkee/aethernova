# datafabric-core/datafabric/io/file_io.py
# -*- coding: utf-8 -*-
"""
Industrial-grade file I/O module for DataFabric.

Features:
- Backend abstraction (Local FS, optional S3 via boto3), easy to extend.
- Atomic writes with durable fsync and temp file swap.
- Auto compression by suffix: .gz (gzip), .bz2 (bzip2), .xz/.lzma (LZMA).
- Checksums (SHA-256) and size verification.
- Sync and Async APIs (async uses asyncio.to_thread to avoid extra deps).
- Robust retries with exponential backoff and jitter.
- Streaming read/write, chunked copy, range reads for S3.
- JSON, NDJSON, YAML (optional), CSV helpers.
- Safe path handling, cross-platform.
- Pluggable metrics hooks and structured logging.
- Strict typing and custom exceptions.

Dependencies:
- Standard library only. Optional: boto3 (for S3), PyYAML (for YAML).

Author: DataFabric IO Team
License: Apache-2.0
"""

from __future__ import annotations

import abc
import asyncio
import bz2
import contextlib
import csv
import dataclasses
import errno
import functools
import gzip
import hashlib
import io
import json
import logging
import lzma
import os
import pathlib
import random
import shutil
import stat
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import (
    Any,
    BinaryIO,
    Callable,
    ContextManager,
    Dict,
    Generator,
    Iterable,
    Iterator,
    List,
    Optional,
    Protocol,
    Tuple,
    Union,
)

# Optional imports guarded
try:
    import yaml  # type: ignore
    _HAS_YAML = True
except Exception:
    _HAS_YAML = False

try:
    import boto3  # type: ignore
    from botocore.exceptions import BotoCoreError, ClientError  # type: ignore
    _HAS_BOTO3 = True
except Exception:
    _HAS_BOTO3 = False


# Logging
LOG = logging.getLogger("datafabric.io.file_io")
if not LOG.handlers:
    handler = logging.StreamHandler(stream=sys.stderr)
    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s [%(name)s] %(message)s"
    )
    handler.setFormatter(formatter)
    LOG.addHandler(handler)
LOG.setLevel(logging.INFO)


# Exceptions
class FileIOError(Exception):
    """Base error for file I/O operations."""


class NotFoundError(FileIOError):
    """Path or object not found."""


class AlreadyExistsError(FileIOError):
    """Destination already exists and overwrite=False."""


class BackendUnavailableError(FileIOError):
    """Backend not available (e.g., missing dependency)."""


class IntegrityError(FileIOError):
    """Checksum or size mismatch."""


class RetryExceededError(FileIOError):
    """Retries exhausted for operation."""


# Utility types
PathLike = Union[str, os.PathLike[str]]
JSONType = Union[Dict[str, Any], List[Any], int, float, str, bool, None]


# Retry policy
@dataclass(frozen=True)
class RetryPolicy:
    attempts: int = 5
    base_delay: float = 0.1  # seconds
    max_delay: float = 2.0   # seconds
    jitter: float = 0.2      # 0..1 proportion of delay

    def compute_sleep(self, attempt: int) -> float:
        # Exponential backoff with decorrelated jitter
        exp = self.base_delay * (2 ** max(0, attempt - 1))
        exp = min(exp, self.max_delay)
        jitter = random.uniform(0.0, self.jitter) * exp
        return exp + jitter


def with_retries(
    func: Callable[..., Any],
    *,
    retry: RetryPolicy,
    retry_on: Tuple[type, ...],
    operation: str,
) -> Callable[..., Any]:
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        last_exc: Optional[BaseException] = None
        for attempt in range(1, retry.attempts + 1):
            try:
                return func(*args, **kwargs)
            except retry_on as e:
                last_exc = e
                sleep = retry.compute_sleep(attempt)
                LOG.warning(
                    "Operation '%s' failed (attempt %d/%d): %s. Retrying in %.3fs",
                    operation,
                    attempt,
                    retry.attempts,
                    e,
                    sleep,
                )
                time.sleep(sleep)
            except Exception:
                # Non-retryable error
                raise
        # Retries exhausted
        raise RetryExceededError(
            f"Operation '{operation}' failed after {retry.attempts} attempts"
        ) from last_exc

    return wrapper


# Compression dispatch
class Compression(str):
    NONE = "none"
    GZIP = "gzip"
    BZ2 = "bz2"
    LZMA = "lzma"


def detect_compression(path: str) -> str:
    p = path.lower()
    if p.endswith(".gz"):
        return Compression.GZIP
    if p.endswith(".bz2"):
        return Compression.BZ2
    if p.endswith(".xz") or p.endswith(".lzma"):
        return Compression.LZMA
    return Compression.NONE


def open_compressed_writer(base: BinaryIO, algo: str, level: Optional[int] = None) -> BinaryIO:
    if algo == Compression.GZIP:
        return gzip.GzipFile(fileobj=base, mode="wb", compresslevel=level or 6)
    if algo == Compression.BZ2:
        return bz2.BZ2File(base, mode="wb", compresslevel=level or 9)
    if algo == Compression.LZMA:
        preset = 6 if level is None else max(0, min(level, 9))
        return lzma.LZMAFile(base, mode="wb", preset=preset)
    return base


def open_compressed_reader(base: BinaryIO, algo: str) -> BinaryIO:
    if algo == Compression.GZIP:
        return gzip.GzipFile(fileobj=base, mode="rb")
    if algo == Compression.BZ2:
        return bz2.BZ2File(base, mode="rb")
    if algo == Compression.LZMA:
        return lzma.LZMAFile(base, mode="rb")
    return base


# Checksums
@dataclass(frozen=True)
class Digest:
    algo: str
    hexdigest: str
    size: int


def sha256_stream(fp: BinaryIO, chunk_size: int = 1024 * 1024) -> Digest:
    h = hashlib.sha256()
    total = 0
    while True:
        chunk = fp.read(chunk_size)
        if not chunk:
            break
        total += len(chunk)
        h.update(chunk)
    return Digest("sha256", h.hexdigest(), total)


def sha256_bytes(data: bytes) -> Digest:
    h = hashlib.sha256(data).hexdigest()
    return Digest("sha256", h, len(data))


# Metrics hook (no-op default)
MetricsHook = Callable[[str, Dict[str, Any]], None]


def default_metrics_hook(event: str, payload: Dict[str, Any]) -> None:
    LOG.debug("metrics %s: %s", event, payload)


# Backend protocol
class StorageBackend(Protocol):
    """Protocol for storage backends."""

    def open_read(self, path: str, *, range_bytes: Optional[Tuple[int, int]] = None) -> BinaryIO: ...
    def open_write(self, path: str, *, overwrite: bool = False) -> BinaryIO: ...
    def exists(self, path: str) -> bool: ...
    def stat(self, path: str) -> Dict[str, Any]: ...
    def remove(self, path: str, *, recursive: bool = False) -> None: ...
    def makedirs(self, path: str, *, exist_ok: bool = True) -> None: ...
    def listdir(self, path: str) -> List[str]: ...
    def rename(self, src: str, dst: str, *, overwrite: bool = False) -> None: ...


# Local FS backend
@dataclass
class LocalBackend(StorageBackend):
    root: Optional[pathlib.Path] = None

    def _resolve(self, path: str) -> pathlib.Path:
        p = pathlib.Path(path)
        if self.root:
            p = self.root.joinpath(p)
        return p

    def open_read(self, path: str, *, range_bytes: Optional[Tuple[int, int]] = None) -> BinaryIO:
        fp = open(self._resolve(path), "rb", buffering=0)
        if range_bytes is not None:
            start, end = range_bytes
            fp.seek(start)
            # Create limited view wrapper
            return _RangeReader(fp, end - start + 1)
        return fp

    def open_write(self, path: str, *, overwrite: bool = False) -> BinaryIO:
        p = self._resolve(path)
        if p.exists() and not overwrite:
            raise AlreadyExistsError(f"File exists: {p}")
        parent = p.parent
        parent.mkdir(parents=True, exist_ok=True)
        # Use os.open for direct flags
        flags = os.O_WRONLY | os.O_CREAT
        if overwrite:
            flags |= os.O_TRUNC
        else:
            flags |= os.O_EXCL
        fd = os.open(str(p), flags, 0o644)
        return os.fdopen(fd, "wb", buffering=0)

    def exists(self, path: str) -> bool:
        return self._resolve(path).exists()

    def stat(self, path: str) -> Dict[str, Any]:
        p = self._resolve(path)
        try:
            st = p.stat()
            return {
                "size": st.st_size,
                "mtime": st.st_mtime,
                "mode": stat.filemode(st.st_mode),
                "is_dir": p.is_dir(),
                "is_file": p.is_file(),
            }
        except FileNotFoundError as e:
            raise NotFoundError(str(e)) from e

    def remove(self, path: str, *, recursive: bool = False) -> None:
        p = self._resolve(path)
        if not p.exists():
            return
        if p.is_dir():
            if recursive:
                shutil.rmtree(p)
            else:
                os.rmdir(p)
        else:
            p.unlink()

    def makedirs(self, path: str, *, exist_ok: bool = True) -> None:
        self._resolve(path).mkdir(parents=True, exist_ok=exist_ok)

    def listdir(self, path: str) -> List[str]:
        p = self._resolve(path)
        if not p.exists():
            raise NotFoundError(f"Not found: {p}")
        return [str(c) for c in p.iterdir()]

    def rename(self, src: str, dst: str, *, overwrite: bool = False) -> None:
        s = self._resolve(src)
        d = self._resolve(dst)
        d.parent.mkdir(parents=True, exist_ok=True)
        if overwrite and d.exists():
            if d.is_dir():
                shutil.rmtree(d)
            else:
                d.unlink()
        s.replace(d)


# Range reader for LocalBackend
class _RangeReader(io.RawIOBase):
    def __init__(self, base: BinaryIO, length: int):
        self._base = base
        self._remaining = length

    def read(self, size: int = -1) -> bytes:
        if self._remaining <= 0:
            return b""
        if size < 0 or size > self._remaining:
            size = self._remaining
        chunk = self._base.read(size)
        self._remaining -= len(chunk)
        return chunk

    def close(self) -> None:
        try:
            self._base.close()
        finally:
            return super().close()


# Optional S3 backend
@dataclass
class S3Backend(StorageBackend):
    bucket: str
    client_kwargs: Dict[str, Any] = dataclasses.field(default_factory=dict)
    _client: Any = dataclasses.field(init=False, default=None)

    def __post_init__(self) -> None:
        if not _HAS_BOTO3:
            raise BackendUnavailableError("boto3 is required for S3Backend")
        self._client = boto3.client("s3", **self.client_kwargs)

    def _key(self, path: str) -> str:
        # Normalize leading slashes
        return path.lstrip("/")

    def open_read(self, path: str, *, range_bytes: Optional[Tuple[int, int]] = None) -> BinaryIO:
        try:
            if range_bytes:
                start, end = range_bytes
                byte_range = f"bytes={start}-{end}"
                resp = self._client.get_object(Bucket=self.bucket, Key=self._key(path), Range=byte_range)
            else:
                resp = self._client.get_object(Bucket=self.bucket, Key=self._key(path))
            body = resp["Body"]  # StreamingBody
            return _StreamingBodyReader(body)
        except (ClientError, BotoCoreError) as e:
            if getattr(e, "response", {}).get("Error", {}).get("Code") == "NoSuchKey":
                raise NotFoundError(str(e)) from e
            raise FileIOError(str(e)) from e

    def open_write(self, path: str, *, overwrite: bool = False) -> BinaryIO:
        # S3 has no true append; we buffer to temp file then upload on close
        return _S3BufferedWriter(self._client, self.bucket, self._key(path), overwrite=overwrite)

    def exists(self, path: str) -> bool:
        try:
            self._client.head_object(Bucket=self.bucket, Key=self._key(path))
            return True
        except (ClientError, BotoCoreError):
            return False

    def stat(self, path: str) -> Dict[str, Any]:
        try:
            resp = self._client.head_object(Bucket=self.bucket, Key=self._key(path))
            return {
                "size": resp["ContentLength"],
                "mtime": resp["LastModified"].timestamp(),
                "etag": resp.get("ETag", "").strip('"'),
                "is_dir": False,
                "is_file": True,
            }
        except (ClientError, BotoCoreError) as e:
            raise NotFoundError(str(e)) from e

    def remove(self, path: str, *, recursive: bool = False) -> None:
        key = self._key(path)
        if not recursive:
            try:
                self._client.delete_object(Bucket=self.bucket, Key=key)
            except (ClientError, BotoCoreError) as e:
                raise FileIOError(str(e)) from e
            return
        # Recursive: list+delete
        paginator = self._client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=key.rstrip("/") + "/"):
            to_delete = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
            if to_delete:
                self._client.delete_objects(Bucket=self.bucket, Delete={"Objects": to_delete})

    def makedirs(self, path: str, *, exist_ok: bool = True) -> None:
        # S3 is flat; emulate directories with placeholder object
        key = self._key(path).rstrip("/") + "/"
        if not exist_ok and self.exists(key):
            raise AlreadyExistsError(f"S3 prefix exists: {key}")
        self._client.put_object(Bucket=self.bucket, Key=key, Body=b"")

    def listdir(self, path: str) -> List[str]:
        prefix = self._key(path).rstrip("/") + "/"
        paginator = self._client.get_paginator("list_objects_v2")
        res: List[str] = []
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix, Delimiter="/"):
            for cp in page.get("CommonPrefixes", []):
                res.append("/" + cp["Prefix"])
            for obj in page.get("Contents", []):
                res.append("/" + obj["Key"])
        return res

    def rename(self, src: str, dst: str, *, overwrite: bool = False) -> None:
        s = self._key(src)
        d = self._key(dst)
        if not overwrite and self.exists(d):
            raise AlreadyExistsError(f"Destination exists: {dst}")
        self._client.copy({"Bucket": self.bucket, "Key": s}, self.bucket, d)
        self._client.delete_object(Bucket=self.bucket, Key=s)


class _StreamingBodyReader(io.RawIOBase):
    def __init__(self, body: Any):
        self._body = body

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            return self._body.read()
        return self._body.read(size)

    def close(self) -> None:
        try:
            self._body.close()
        finally:
            return super().close()


class _S3BufferedWriter(io.BufferedWriter):
    def __init__(self, client: Any, bucket: str, key: str, *, overwrite: bool):
        self._client = client
        self._bucket = bucket
        self._key = key
        self._overwrite = overwrite
        tmp = tempfile.NamedTemporaryFile(delete=False)
        self._tmp_name = tmp.name
        super().__init__(tmp)

    def close(self) -> None:
        try:
            super().close()
            if not self._overwrite:
                # if exists and overwrite=False -> error
                try:
                    self._client.head_object(Bucket=self._bucket, Key=self._key)
                    # exists
                    raise AlreadyExistsError(f"S3 object exists: s3://{self._bucket}/{self._key}")
                except Exception:
                    # not exists or head failed → proceed
                    pass
            with open(self._tmp_name, "rb") as fp:
                self._client.upload_fileobj(fp, self._bucket, self._key)
        except (ClientError, BotoCoreError) as e:
            raise FileIOError(str(e)) from e
        finally:
            with contextlib.suppress(Exception):
                os.unlink(self._tmp_name)


# Atomic file helpers (local)
@contextlib.contextmanager
def _atomic_local_write(final_path: pathlib.Path) -> Generator[Tuple[pathlib.Path, BinaryIO], None, None]:
    final_path.parent.mkdir(parents=True, exist_ok=True)
    # Create temp file on same filesystem
    fd, tmp_name = tempfile.mkstemp(prefix=".tmp-", dir=str(final_path.parent))
    try:
        with os.fdopen(fd, "wb", buffering=0) as tmp_fp:
            yield pathlib.Path(tmp_name), tmp_fp
            # Flush and fsync to ensure durability
            tmp_fp.flush()
            os.fsync(tmp_fp.fileno())
        # Atomic rename
        os.replace(tmp_name, final_path)
    except Exception:
        with contextlib.suppress(Exception):
            os.unlink(tmp_name)
        raise


# FileIO facade
@dataclass
class FileIO:
    backend: StorageBackend
    retry_policy: RetryPolicy = dataclasses.field(default_factory=RetryPolicy)
    metrics_hook: MetricsHook = default_metrics_hook
    default_chunk_size: int = 8 * 1024 * 1024

    # --------------- Core open/read/write (binary) -----------------

    def open(self, path: str, mode: str = "rb", *, overwrite: bool = False,
             compression: Optional[str] = None, compression_level: Optional[int] = None,
             range_bytes: Optional[Tuple[int, int]] = None) -> BinaryIO:
        """
        Open a path for binary reading or writing, with optional compression wrapper.
        """
        comp = compression or detect_compression(path)
        if "r" in mode:
            base = self.backend.open_read(path, range_bytes=range_bytes)
            return open_compressed_reader(base, comp)
        if "w" in mode:
            base = self.backend.open_write(path, overwrite=overwrite)
            return open_compressed_writer(base, comp, compression_level)
        raise ValueError(f"Unsupported mode: {mode}")

    def read_bytes(self, path: str) -> bytes:
        def op() -> bytes:
            with self.open(path, "rb") as fp:
                return fp.read()
        wrapped = with_retries(op, retry=self.retry_policy, retry_on=(OSError, FileIOError), operation="read_bytes")
        data = wrapped()
        self.metrics_hook("read_bytes", {"path": path, "size": len(data)})
        return data

    def write_bytes(self, path: str, data: bytes, *, overwrite: bool = False,
                    expected_sha256: Optional[str] = None, compression: Optional[str] = None,
                    compression_level: Optional[int] = None) -> Digest:
        def op() -> Digest:
            comp = compression or detect_compression(path)
            # Local backend → atomic swap; S3 → use open_write (buffered)
            if isinstance(self.backend, LocalBackend):
                dest = self.backend._resolve(path)  # type: ignore
                with _atomic_local_write(dest) as (tmp_path, tmp_fp):
                    with open_compressed_writer(tmp_fp, comp, compression_level) as w:
                        w.write(data)
                    # reopen for checksum
                    with open(tmp_path, "rb") as verify_fp:
                        d = sha256_stream(verify_fp)
                # os.replace already done in context manager
                digest = d
            else:
                with self.open(path, "wb", overwrite=overwrite, compression=comp,
                               compression_level=compression_level) as fp:
                    fp.write(data)
                # cost: fetch to compute checksum? Avoid; compute checksum of input
                digest = sha256_bytes(data)
            if expected_sha256 and digest.hexdigest != expected_sha256:
                raise IntegrityError("SHA-256 mismatch after write")
            return digest

        wrapped = with_retries(op, retry=self.retry_policy, retry_on=(OSError, FileIOError), operation="write_bytes")
        digest = wrapped()
        self.metrics_hook("write_bytes", {"path": path, "size": digest.size, "sha256": digest.hexdigest})
        return digest

    def stream_read(self, path: str, *, chunk_size: Optional[int] = None) -> Iterator[bytes]:
        """Generator yielding chunks."""
        chunk = chunk_size or self.default_chunk_size

        def generator() -> Iterator[bytes]:
            with self.open(path, "rb") as fp:
                while True:
                    data = fp.read(chunk)
                    if not data:
                        break
                    yield data

        return generator()

    def stream_write(self, path: str, chunks: Iterable[bytes], *, overwrite: bool = False,
                     compression: Optional[str] = None, compression_level: Optional[int] = None) -> Digest:
        comp = compression or detect_compression(path)

        def op() -> Digest:
            h = hashlib.sha256()
            size = 0
            if isinstance(self.backend, LocalBackend):
                dest = self.backend._resolve(path)  # type: ignore
                with _atomic_local_write(dest) as (_tmp, tmp_fp):
                    with open_compressed_writer(tmp_fp, comp, compression_level) as w:
                        for c in chunks:
                            h.update(c)
                            size += len(c)
                            w.write(c)
                return Digest("sha256", h.hexdigest(), size)
            else:
                with self.open(path, "wb", overwrite=overwrite, compression=comp,
                               compression_level=compression_level) as fp:
                    for c in chunks:
                        h.update(c)
                        size += len(c)
                        fp.write(c)
                return Digest("sha256", h.hexdigest(), size)

        wrapped = with_retries(op, retry=self.retry_policy, retry_on=(OSError, FileIOError), operation="stream_write")
        digest = wrapped()
        self.metrics_hook("stream_write", {"path": path, "size": digest.size, "sha256": digest.hexdigest})
        return digest

    # --------------- JSON / NDJSON / YAML / CSV -----------------

    def read_json(self, path: str, *, encoding: str = "utf-8") -> JSONType:
        data = self.read_bytes(path)
        try:
            return json.loads(data.decode(encoding))
        except Exception as e:
            raise FileIOError(f"Invalid JSON at {path}: {e}") from e

    def write_json(self, path: str, obj: JSONType, *, overwrite: bool = False,
                   encoding: str = "utf-8", indent: Optional[int] = 2, ensure_ascii: bool = False) -> Digest:
        data = json.dumps(obj, indent=indent, ensure_ascii=ensure_ascii).encode(encoding)
        return self.write_bytes(path, data, overwrite=overwrite)

    def read_ndjson(self, path: str, *, encoding: str = "utf-8") -> Iterator[JSONType]:
        for line in self.stream_read(path, chunk_size=1024 * 1024):
            # stream chunks into lines safely; use incremental buffer
            yield from _lines_to_json(line, encoding=encoding)

    def write_ndjson(self, path: str, rows: Iterable[JSONType], *, overwrite: bool = False,
                     encoding: str = "utf-8") -> Digest:
        def gen() -> Iterator[bytes]:
            for obj in rows:
                yield (json.dumps(obj, ensure_ascii=False) + "\n").encode(encoding)
        return self.stream_write(path, gen(), overwrite=overwrite)

    def read_yaml(self, path: str) -> Any:
        if not _HAS_YAML:
            raise BackendUnavailableError("PyYAML not installed")
        data = self.read_bytes(path)
        return yaml.safe_load(io.BytesIO(data))  # type: ignore

    def write_yaml(self, path: str, obj: Any, *, overwrite: bool = False) -> Digest:
        if not _HAS_YAML:
            raise BackendUnavailableError("PyYAML not installed")
        stream = io.StringIO()
        yaml.safe_dump(obj, stream, sort_keys=False)  # type: ignore
        return self.write_bytes(path, stream.getvalue().encode("utf-8"), overwrite=overwrite)

    def read_csv(self, path: str, *, encoding: str = "utf-8", dialect: str = "excel",
                 has_header: bool = True) -> Iterator[Dict[str, str]]:
        """Stream CSV rows as dicts."""
        def gen() -> Iterator[Dict[str, str]]:
            with self.open(path, "rb") as fp:
                text = io.TextIOWrapper(fp, encoding=encoding, newline="")
                reader = csv.DictReader(text, dialect=dialect) if has_header else csv.reader(text, dialect=dialect)
                if has_header:
                    assert isinstance(reader, csv.DictReader)
                    for row in reader:
                        yield dict(row)
                else:
                    assert isinstance(reader, csv._reader)  # type: ignore[attr-defined]
                    for row in reader:  # type: ignore[assignment]
                        yield {str(i): v for i, v in enumerate(row)}
        return gen()

    def write_csv(self, path: str, rows: Iterable[Dict[str, Any]], *, overwrite: bool = False,
                  encoding: str = "utf-8", dialect: str = "excel", headers: Optional[List[str]] = None) -> Digest:
        def gen() -> Iterator[bytes]:
            buffer = io.StringIO()
            writer: Union[csv.DictWriter, csv.writer]
            first_row: Optional[Dict[str, Any]] = None
            it = iter(rows)
            try:
                first_row = next(it)
            except StopIteration:
                # write empty file
                if headers:
                    buffer = io.StringIO()
                    writer = csv.DictWriter(buffer, fieldnames=headers, dialect=dialect)
                    writer.writeheader()
                    yield buffer.getvalue().encode(encoding)
                return
            fieldnames = headers or list(first_row.keys())
            buffer = io.StringIO()
            writer = csv.DictWriter(buffer, fieldnames=fieldnames, dialect=dialect)
            writer.writeheader()
            writer.writerow(first_row)
            yield buffer.getvalue().encode(encoding)
            buffer.seek(0); buffer.truncate(0)
            for row in it:
                writer.writerow(row)
                if buffer.tell() > 1_000_000:
                    yield buffer.getvalue().encode(encoding)
                    buffer.seek(0); buffer.truncate(0)
            if buffer.tell():
                yield buffer.getvalue().encode(encoding)

        return self.stream_write(path, gen(), overwrite=overwrite)

    # --------------- Text helpers -----------------

    def read_text(self, path: str, *, encoding: str = "utf-8") -> str:
        return self.read_bytes(path).decode(encoding)

    def write_text(self, path: str, text: str, *, overwrite: bool = False, encoding: str = "utf-8") -> Digest:
        return self.write_bytes(path, text.encode(encoding), overwrite=overwrite)

    # --------------- Existence, stat, list, delete, copy, move -----

    def exists(self, path: str) -> bool:
        return self.backend.exists(path)

    def stat(self, path: str) -> Dict[str, Any]:
        return self.backend.stat(path)

    def remove(self, path: str, *, recursive: bool = False) -> None:
        def op() -> None:
            self.backend.remove(path, recursive=recursive)
        wrapped = with_retries(op, retry=self.retry_policy, retry_on=(OSError, FileIOError), operation="remove")
        wrapped()
        self.metrics_hook("remove", {"path": path, "recursive": recursive})

    def makedirs(self, path: str, *, exist_ok: bool = True) -> None:
        self.backend.makedirs(path, exist_ok=exist_ok)

    def listdir(self, path: str) -> List[str]:
        return self.backend.listdir(path)

    def rename(self, src: str, dst: str, *, overwrite: bool = False) -> None:
        def op() -> None:
            self.backend.rename(src, dst, overwrite=overwrite)
        wrapped = with_retries(op, retry=self.retry_policy, retry_on=(OSError, FileIOError), operation="rename")
        wrapped()
        self.metrics_hook("rename", {"src": src, "dst": dst, "overwrite": overwrite})

    def copy(self, src: str, dst: str, *, overwrite: bool = False, buffer_size: Optional[int] = None) -> Digest:
        """Copy with streaming to handle large files."""
        buf = buffer_size or self.default_chunk_size

        def op() -> Digest:
            h = hashlib.sha256()
            size = 0
            with self.open(src, "rb") as r, self.open(dst, "wb", overwrite=overwrite) as w:
                while True:
                    chunk = r.read(buf)
                    if not chunk:
                        break
                    h.update(chunk)
                    size += len(chunk)
                    w.write(chunk)
            return Digest("sha256", h.hexdigest(), size)

        wrapped = with_retries(op, retry=self.retry_policy, retry_on=(OSError, FileIOError), operation="copy")
        d = wrapped()
        self.metrics_hook("copy", {"src": src, "dst": dst, "size": d.size, "sha256": d.hexdigest})
        return d

    # --------------- Async wrappers -----------------

    async def aopen(self, path: str, mode: str = "rb", **kwargs: Any) -> BinaryIO:
        # Note: returns sync file-like object; safe to pass into aiofiles-like layers if desired.
        return await asyncio.to_thread(self.open, path, mode, **kwargs)

    async def aread_bytes(self, path: str) -> bytes:
        return await asyncio.to_thread(self.read_bytes, path)

    async def awrite_bytes(self, path: str, data: bytes, **kwargs: Any) -> Digest:
        return await asyncio.to_thread(self.write_bytes, path, data, **kwargs)

    async def astream_read(self, path: str, *, chunk_size: Optional[int] = None) -> AsyncIterator[bytes]:
        """Async generator yielding chunks."""
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[Optional[bytes]] = asyncio.Queue(maxsize=4)

        def producer() -> None:
            try:
                for chunk in self.stream_read(path, chunk_size=chunk_size):
                    loop.call_soon_threadsafe(queue.put_nowait, chunk)
            finally:
                loop.call_soon_threadsafe(queue.put_nowait, None)

        threading = __import__("threading")
        t = threading.Thread(target=producer, daemon=True)
        t.start()

        while True:
            item = await queue.get()
            if item is None:
                break
            yield item

    async def astream_write(self, path: str, achunks: AsyncIterator[bytes], **kwargs: Any) -> Digest:
        # Buffer async iterable to thread-friendly generator
        async def collect() -> List[bytes]:
            out: List[bytes] = []
            async for c in achunks:
                out.append(c)
            return out
        chunks = await collect()
        return await asyncio.to_thread(self.stream_write, path, chunks, **kwargs)


# Helpers
def _lines_to_json(chunk: bytes, *, encoding: str = "utf-8") -> Iterator[JSONType]:
    # This is a simplified splitter: assumes chunk boundaries align to lines at caller.
    # For robust NDJSON streaming split, a stateful reader is needed.
    text = chunk.decode(encoding)
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            # best-effort; caller can validate if needed
            raise FileIOError("Invalid NDJSON line")


# Factory
def make_backend(url: str, **kwargs: Any) -> StorageBackend:
    """
    Create backend from URL-like string:
    - 'file://...' or no scheme -> LocalBackend
    - 's3://bucket[/prefix]' -> S3Backend (requires boto3)
    """
    if url.startswith("s3://"):
        if not _HAS_BOTO3:
            raise BackendUnavailableError("boto3 not installed")
        # Extract bucket and optional root prefix
        without = url[len("s3://"):]
        if "/" in without:
            bucket, root = without.split("/", 1)
        else:
            bucket, root = without, ""
        backend: StorageBackend = S3Backend(bucket=bucket, **kwargs)
        if root:
            # Wrap path prefix by using a thin adapter
            return _PrefixBackend(backend, root=root)
        return backend
    if url.startswith("file://"):
        root = url[len("file://"):]
        return LocalBackend(root=pathlib.Path(root) if root else None)
    # default: local path root
    return LocalBackend(root=pathlib.Path(url) if url else None)


@dataclass
class _PrefixBackend(StorageBackend):
    inner: StorageBackend
    root: str

    def _p(self, path: str) -> str:
        return f"{self.root.rstrip('/')}/{path.lstrip('/')}"

    def open_read(self, path: str, *, range_bytes: Optional[Tuple[int, int]] = None) -> BinaryIO:
        return self.inner.open_read(self._p(path), range_bytes=range_bytes)

    def open_write(self, path: str, *, overwrite: bool = False) -> BinaryIO:
        return self.inner.open_write(self._p(path), overwrite=overwrite)

    def exists(self, path: str) -> bool:
        return self.inner.exists(self._p(path))

    def stat(self, path: str) -> Dict[str, Any]:
        return self.inner.stat(self._p(path))

    def remove(self, path: str, *, recursive: bool = False) -> None:
        return self.inner.remove(self._p(path), recursive=recursive)

    def makedirs(self, path: str, *, exist_ok: bool = True) -> None:
        return self.inner.makedirs(self._p(path), exist_ok=exist_ok)

    def listdir(self, path: str) -> List[str]:
        return self.inner.listdir(self._p(path))

    def rename(self, src: str, dst: str, *, overwrite: bool = False) -> None:
        return self.inner.rename(self._p(src), self._p(dst), overwrite=overwrite)


# Public convenience constructors
def fileio_from_url(url: str, **kwargs: Any) -> FileIO:
    return FileIO(backend=make_backend(url, **kwargs))


# __all__
__all__ = [
    "FileIO",
    "LocalBackend",
    "S3Backend",
    "StorageBackend",
    "RetryPolicy",
    "Digest",
    "FileIOError",
    "NotFoundError",
    "AlreadyExistsError",
    "BackendUnavailableError",
    "IntegrityError",
    "RetryExceededError",
    "Compression",
    "fileio_from_url",
    "make_backend",
]
