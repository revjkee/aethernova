# neuroforge-core/neuroforge/utils/io.py
from __future__ import annotations

import asyncio
import bz2
import csv
import errno
import gzip
import hashlib
import io
import json
import logging
import lzma
import mimetypes
import os
import shutil
import sys
import tempfile
import time
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Literal, Sequence

# -------- Optional deps (graceful if absent) --------
try:  # Fast JSON (optional)
    import orjson  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    orjson = None  # type: ignore[assignment]

try:  # YAML (optional)
    import yaml  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

try:  # TOML read (3.11+)
    import tomllib  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

try:  # TOML write (optional)
    import tomli_w  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    tomli_w = None  # type: ignore[assignment]

# -------- Logging --------
logger = logging.getLogger(__name__)

# -------- Constants --------
DEFAULT_ENCODING = "utf-8"
READ_CHUNK = 1024 * 1024
HASH_CHUNK = 1024 * 1024
_DEFAULT_FILE_MODE = 0o644

Compression = Literal["none", "gz", "bz2", "xz"]

__all__ = [
    "IOService",
    "FileLock",
    "safe_path",
    "open_file",
    "atomic_write_bytes",
    "atomic_write_text",
]


# =========================
# Errors
# =========================
class IOServiceError(Exception):
    """Base IO error."""


class UnsafePathError(IOServiceError):
    """Raised when a path escapes base directory or violates policy."""


class SizeLimitExceeded(IOServiceError):
    """Raised when reading exceeds the configured size limit."""


class OptionalDependencyMissing(IOServiceError):
    """Raised when an optional feature is requested but dependency is missing."""


# =========================
# Cross-platform file lock
# =========================
class FileLock:
    """
    Cross-platform interprocess file lock (advisory).
    - Unix: fcntl.flock
    - Windows: msvcrt.locking (best-effort)
    """

    def __init__(self, path: Path, timeout: float | None = 10.0) -> None:
        self.path = Path(path)
        self.timeout = timeout
        self._fh: io.TextIOWrapper | None = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(self.path, "a+", encoding=DEFAULT_ENCODING)
        self._fh = fh

        start = time.time()
        if os.name == "nt":
            import msvcrt  # type: ignore

            while True:
                try:
                    # Lock 1 byte (advisory). Non-blocking emulate via retry.
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if self.timeout is not None and (time.time() - start) > self.timeout:
                        raise TimeoutError(f"Lock timeout: {self.path}") from None
                    time.sleep(0.05)
        else:
            import fcntl  # type: ignore

            while True:
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError as e:
                    if e.errno not in (errno.EAGAIN, errno.EACCES):
                        raise
                    if self.timeout is not None and (time.time() - start) > self.timeout:
                        raise TimeoutError(f"Lock timeout: {self.path}") from None
                    time.sleep(0.05)

    def release(self) -> None:
        if not self._fh:
            return
        fh = self._fh
        self._fh = None

        if os.name == "nt":
            import msvcrt  # type: ignore

            with suppress(Exception):
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl  # type: ignore

            with suppress(Exception):
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

        with suppress(Exception):
            fh.close()

    def __enter__(self) -> "FileLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()


# =========================
# Path utilities
# =========================
def safe_path(
    path: str | os.PathLike[str],
    base_dir: str | os.PathLike[str] | None,
    allow_symlinks: bool = False,
) -> Path:
    """
    Resolve 'path' safely under 'base_dir'.
    - Denies path traversal outside base_dir.
    - Optionally denies symlinks in the resolved parents.

    If base_dir is None, resolves absolute path and returns it.
    """
    p = Path(path)
    if base_dir is None:
        rp = p.resolve(strict=False)
        return rp

    base = Path(base_dir).resolve(strict=True)
    rp = (base / p).resolve(strict=False) if not p.is_absolute() else p.resolve(strict=False)

    # Keep inside base
    if base != rp and base not in rp.parents:
        raise UnsafePathError(f"Path escapes base_dir: {rp} not under {base}")

    if not allow_symlinks:
        # Check existing parents for symlinks
        with suppress(Exception):
            current = rp
            while True:
                parent = current if current.is_dir() else current.parent
                if parent == parent.parent:  # root reached
                    break
                if parent.exists() and parent.is_symlink():
                    raise UnsafePathError(f"Symlink detected in path parents: {parent}")
                current = parent

    return rp


# =========================
# Low-level fsync helpers
# =========================
def _fsync_file(fd: int) -> None:
    with suppress(Exception):
        os.fsync(fd)


def _fsync_dir(dir_path: Path) -> None:
    if os.name == "nt":
        # Windows: no O_DIRECTORY, best-effort skip
        return
    try:
        fd = os.open(str(dir_path), os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except Exception:  # pragma: no cover
        logger.debug("Directory fsync skipped: %s", dir_path, exc_info=True)


# =========================
# Compression-aware open
# =========================
def _detect_compression(path: Path) -> Compression:
    s = str(path).lower()
    if s.endswith(".gz"):
        return "gz"
    if s.endswith(".bz2"):
        return "bz2"
    if s.endswith(".xz") or s.endswith(".lzma"):
        return "xz"
    return "none"


def open_file(
    path: str | os.PathLike[str],
    mode: str = "rb",
    encoding: str | None = None,
    newline: str | None = None,
):
    """
    Open file with transparent compression based on extension.
    Supports .gz, .bz2, .xz; falls back to builtin open().

    Text mode: pass encoding/newline; Binary mode ignores them.
    """
    p = Path(path)
    comp = _detect_compression(p)

    is_text = "b" not in mode
    if comp == "gz":
        return gzip.open(p, mode, encoding=encoding if is_text else None, newline=newline if is_text else None)
    if comp == "bz2":
        return bz2.open(p, mode, encoding=encoding if is_text else None, newline=newline if is_text else None)
    if comp == "xz":
        return lzma.open(p, mode, encoding=encoding if is_text else None, newline=newline if is_text else None)
    return open(p, mode, encoding=encoding if is_text else None, newline=newline if is_text else None)


# =========================
# Atomic writes
# =========================
def _ensure_parents(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def atomic_write_bytes(
    path: str | os.PathLike[str],
    data: bytes,
    *,
    make_parents: bool = True,
    file_mode: int = _DEFAULT_FILE_MODE,
    fsync_dir: bool = True,
) -> Path:
    """
    Atomic write for bytes:
    - writes to same-directory temporary file
    - fsync file
    - os.replace to final path
    - optional fsync parent directory

    Returns final Path.
    """
    dst = Path(path)
    if make_parents:
        _ensure_parents(dst)

    tmp_fd, tmp_name = tempfile.mkstemp(dir=str(dst.parent))
    try:
        with os.fdopen(tmp_fd, "wb") as tf:
            tf.write(data)
            _fsync_file(tf.fileno())

        os.chmod(tmp_name, file_mode)
        os.replace(tmp_name, dst)
        if fsync_dir:
            _fsync_dir(dst.parent)
    except Exception:
        with suppress(Exception):
            os.unlink(tmp_name)
        raise
    return dst


def atomic_write_text(
    path: str | os.PathLike[str],
    text: str,
    *,
    encoding: str = DEFAULT_ENCODING,
    newline: str | None = None,
    make_parents: bool = True,
    file_mode: int = _DEFAULT_FILE_MODE,
    fsync_dir: bool = True,
) -> Path:
    data = text.encode(encoding)
    return atomic_write_bytes(
        path,
        data,
        make_parents=make_parents,
        file_mode=file_mode,
        fsync_dir=fsync_dir,
    )


# =========================
# IO Service
# =========================
@dataclass(slots=True)
class IOService:
    """
    High-reliability IO facade bound to a base_dir (optional).
    All relative paths are resolved under base_dir and sanitized.
    """
    base_dir: Path | None = None
    default_encoding: str = DEFAULT_ENCODING

    # ---------- Path ----------
    def resolve(self, rel: str | os.PathLike[str], *, allow_symlinks: bool = False) -> Path:
        return safe_path(rel, self.base_dir, allow_symlinks=allow_symlinks)

    # ---------- Exists/size ----------
    def exists(self, rel: str | os.PathLike[str]) -> bool:
        return self.resolve(rel).exists()

    def size(self, rel: str | os.PathLike[str]) -> int:
        return self.resolve(rel).stat().st_size

    # ---------- Read (bytes/text) with limits ----------
    def read_bytes(self, rel: str | os.PathLike[str], *, max_bytes: int | None = None) -> bytes:
        path = self.resolve(rel)
        # Pre-check on uncompressed files
        if max_bytes is not None and _detect_compression(path) == "none":
            sz = path.stat().st_size
            if sz > max_bytes:
                raise SizeLimitExceeded(f"File {path} size {sz} > max {max_bytes}")

        with open_file(path, "rb") as f:
            if max_bytes is None:
                return f.read()
            # Stream enforce
            out = bytearray()
            remaining = max_bytes
            while remaining > 0:
                chunk = f.read(min(READ_CHUNK, remaining))
                if not chunk:
                    break
                out += chunk
                remaining -= len(chunk)
            # If file still has data -> limit exceeded
            extra = f.read(1)
            if extra:
                raise SizeLimitExceeded(f"Read limit {max_bytes} exceeded for {path}")
            return bytes(out)

    def read_text(
        self,
        rel: str | os.PathLike[str],
        *,
        encoding: str | None = None,
        newline: str | None = None,
        max_bytes: int | None = None,
    ) -> str:
        data = self.read_bytes(rel, max_bytes=max_bytes)
        return data.decode(encoding or self.default_encoding)

    # ---------- Write (bytes/text) atomic ----------
    def write_bytes(
        self,
        rel: str | os.PathLike[str],
        data: bytes,
        *,
        atomic: bool = True,
        file_mode: int = _DEFAULT_FILE_MODE,
    ) -> Path:
        path = self.resolve(rel)
        if atomic:
            return atomic_write_bytes(path, data, file_mode=file_mode)
        else:
            _ensure_parents(path)
            with open_file(path, "wb") as f:
                f.write(data)
                _fsync_file(f.fileno())
            _fsync_dir(path.parent)
            return path

    def write_text(
        self,
        rel: str | os.PathLike[str],
        text: str,
        *,
        encoding: str | None = None,
        newline: str | None = None,
        atomic: bool = True,
        file_mode: int = _DEFAULT_FILE_MODE,
    ) -> Path:
        data = text.encode(encoding or self.default_encoding)
        return self.write_bytes(rel, data, atomic=atomic, file_mode=file_mode)

    # ---------- Append ----------
    def append_text(
        self,
        rel: str | os.PathLike[str],
        text: str,
        *,
        encoding: str | None = None,
        newline: str | None = None,
    ) -> Path:
        path = self.resolve(rel)
        _ensure_parents(path)
        with open_file(path, "a", encoding=encoding or self.default_encoding, newline=newline) as f:
            f.write(text)
            if hasattr(f, "fileno"):
                _fsync_file(f.fileno())
        _fsync_dir(path.parent)
        return path

    def append_bytes(self, rel: str | os.PathLike[str], data: bytes) -> Path:
        path = self.resolve(rel)
        _ensure_parents(path)
        with open_file(path, "ab") as f:
            f.write(data)
            if hasattr(f, "fileno"):
                _fsync_file(f.fileno())
        _fsync_dir(path.parent)
        return path

    # ---------- Streaming ----------
    def iter_lines(
        self,
        rel: str | os.PathLike[str],
        *,
        encoding: str | None = None,
        strip_newline: bool = True,
    ) -> Iterator[str]:
        path = self.resolve(rel)
        with open_file(path, "rt", encoding=encoding or self.default_encoding) as f:
            for line in f:
                yield line.rstrip("\n") if strip_newline else line

    # ---------- JSON ----------
    def read_json(self, rel: str | os.PathLike[str], *, max_bytes: int | None = None) -> Any:
        raw = self.read_bytes(rel, max_bytes=max_bytes)
        if orjson:
            return orjson.loads(raw)
        return json.loads(raw.decode(self.default_encoding))

    def write_json(
        self,
        rel: str | os.PathLike[str],
        obj: Any,
        *,
        pretty: bool = True,
        atomic: bool = True,
    ) -> Path:
        if orjson:
            opts = 0
            if pretty:
                opts |= getattr(orjson, "OPT_INDENT_2", 0) | getattr(orjson, "OPT_SORT_KEYS", 0)
            data = orjson.dumps(obj, option=opts)
        else:
            data = (json.dumps(obj, indent=2 if pretty else None, sort_keys=pretty) + "\n").encode(self.default_encoding)
        return self.write_bytes(rel, data, atomic=atomic)

    # ---------- YAML (optional) ----------
    def read_yaml(self, rel: str | os.PathLike[str], *, max_bytes: int | None = None) -> Any:
        if yaml is None:
            raise OptionalDependencyMissing("PyYAML is not installed")
        text = self.read_text(rel, max_bytes=max_bytes)
        return yaml.safe_load(text)

    def write_yaml(self, rel: str | os.PathLike[str], obj: Any, *, atomic: bool = True) -> Path:
        if yaml is None:
            raise OptionalDependencyMissing("PyYAML is not installed")
        text = yaml.safe_dump(obj, sort_keys=True)
        return self.write_text(rel, text, atomic=atomic)

    # ---------- TOML ----------
    def read_toml(self, rel: str | os.PathLike[str], *, max_bytes: int | None = None) -> dict[str, Any]:
        if tomllib is None:
            raise OptionalDependencyMissing("tomllib (Python 3.11+) is not available")
        raw = self.read_bytes(rel, max_bytes=max_bytes)
        return tomllib.loads(raw.decode(self.default_encoding))

    def write_toml(self, rel: str | os.PathLike[str], obj: dict[str, Any], *, atomic: bool = True) -> Path:
        if tomli_w is None:
            raise OptionalDependencyMissing("tomli_w is not installed for TOML writing")
        data = tomli_w.dumps(obj).encode(self.default_encoding)
        return self.write_bytes(rel, data, atomic=atomic)

    # ---------- CSV ----------
    def read_csv_dicts(
        self,
        rel: str | os.PathLike[str],
        *,
        delimiter: str = ",",
        quotechar: str = '"',
        encoding: str | None = None,
        limit_rows: int | None = None,
    ) -> list[dict[str, str]]:
        path = self.resolve(rel)
        rows: list[dict[str, str]] = []
        with open_file(path, "rt", encoding=encoding or self.default_encoding, newline="") as f:
            reader = csv.DictReader(f, delimiter=delimiter, quotechar=quotechar)
            for i, row in enumerate(reader, 1):
                rows.append({k: (v if v is not None else "") for k, v in row.items()})
                if limit_rows is not None and i >= limit_rows:
                    break
        return rows

    def write_csv_dicts(
        self,
        rel: str | os.PathLike[str],
        rows: Sequence[dict[str, Any]],
        *,
        fieldnames: Sequence[str] | None = None,
        delimiter: str = ",",
        quotechar: str = '"',
        encoding: str | None = None,
        atomic: bool = True,
    ) -> Path:
        if not rows and not fieldnames:
            raise ValueError("Either rows must be non-empty or fieldnames provided")
        fnames = list(fieldnames or rows[0].keys())
        # Write to memory then atomic write
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fnames, delimiter=delimiter, quotechar=quotechar, lineterminator="\n")
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in fnames})
        text = buf.getvalue()
        return self.write_text(rel, text, encoding=encoding or self.default_encoding, atomic=atomic)

    # ---------- Hash / checksum ----------
    def file_hash(self, rel: str | os.PathLike[str], *, algo: str = "sha256") -> str:
        path = self.resolve(rel)
        h = hashlib.new(algo)
        with open_file(path, "rb") as f:
            while True:
                chunk = f.read(HASH_CHUNK)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    # ---------- Backups (rotation) ----------
    def rotate_backups(self, rel: str | os.PathLike[str], *, keep: int = 3) -> None:
        """
        Keep at most 'keep' backups like file.ext.bak1, .bak2, ...
        """
        path = self.resolve(rel)
        if keep <= 0 or not path.exists():
            return
        # Shift older
        for i in range(keep, 0, -1):
            b = path.with_suffix(path.suffix + f".bak{i}")
            nb = path.with_suffix(path.suffix + f".bak{i+1}")
            if b.exists():
                with suppress(Exception):
                    if nb.exists():
                        nb.unlink()
                    b.rename(nb)
        # Create .bak1
        b1 = path.with_suffix(path.suffix + ".bak1")
        with suppress(Exception):
            if b1.exists():
                b1.unlink()
        shutil.copy2(path, b1)

    # ---------- Mimetype ----------
    def guess_mime(self, rel: str | os.PathLike[str]) -> str | None:
        path = self.resolve(rel)
        mime, _ = mimetypes.guess_type(str(path))
        return mime

    # ---------- Locks ----------
    @contextmanager
    def locked(self, rel: str | os.PathLike[str], *, timeout: float | None = 10.0) -> Iterator[None]:
        lock_path = self.resolve(str(rel) + ".lock")
        with FileLock(lock_path, timeout=timeout):
            yield

    # ---------- Async wrappers (thread offloading) ----------
    async def aread_bytes(self, rel: str | os.PathLike[str], *, max_bytes: int | None = None) -> bytes:
        return await asyncio.to_thread(self.read_bytes, rel, max_bytes=max_bytes)

    async def aread_text(
        self,
        rel: str | os.PathLike[str],
        *,
        encoding: str | None = None,
        newline: str | None = None,
        max_bytes: int | None = None,
    ) -> str:
        return await asyncio.to_thread(self.read_text, rel, encoding=encoding, newline=newline, max_bytes=max_bytes)

    async def awrite_bytes(
        self,
        rel: str | os.PathLike[str],
        data: bytes,
        *,
        atomic: bool = True,
        file_mode: int = _DEFAULT_FILE_MODE,
    ) -> Path:
        return await asyncio.to_thread(self.write_bytes, rel, data, atomic=atomic, file_mode=file_mode)

    async def awrite_text(
        self,
        rel: str | os.PathLike[str],
        text: str,
        *,
        encoding: str | None = None,
        newline: str | None = None,
        atomic: bool = True,
        file_mode: int = _DEFAULT_FILE_MODE,
    ) -> Path:
        return await asyncio.to_thread(
            self.write_text,
            rel,
            text,
            encoding=encoding,
            newline=newline,
            atomic=atomic,
            file_mode=file_mode,
        )

    async def awrite_json(self, rel: str | os.PathLike[str], obj: Any, *, pretty: bool = True, atomic: bool = True) -> Path:
        return await asyncio.to_thread(self.write_json, rel, obj, pretty=pretty, atomic=atomic)

    async def aread_json(self, rel: str | os.PathLike[str], *, max_bytes: int | None = None) -> Any:
        return await asyncio.to_thread(self.read_json, rel, max_bytes=max_bytes)


# =========================
# Module-level shortcuts
# =========================
def _default_service() -> IOService:
    return IOService(base_dir=None)


def read_bytes(path: str | os.PathLike[str], *, max_bytes: int | None = None) -> bytes:
    return _default_service().read_bytes(path, max_bytes=max_bytes)


def read_text(path: str | os.PathLike[str], *, encoding: str | None = None, max_bytes: int | None = None) -> str:
    return _default_service().read_text(path, encoding=encoding, max_bytes=max_bytes)


def write_bytes(path: str | os.PathLike[str], data: bytes, *, atomic: bool = True) -> Path:
    return _default_service().write_bytes(path, data, atomic=atomic)


def write_text(path: str | os.PathLike[str], text: str, *, encoding: str | None = None, atomic: bool = True) -> Path:
    return _default_service().write_text(path, text, encoding=encoding, atomic=atomic)
