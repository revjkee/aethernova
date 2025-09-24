# oblivionvault-core/oblivionvault/archive/retrieval.py
# Industrial-grade asynchronous archive retrieval for OblivionVault.
# Stdlib-only. Python 3.11+ recommended.
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import hashlib
import io
import json
import logging
import os
import time
from asyncio import AbstractEventLoop
from pathlib import Path
from typing import (
    AsyncIterator,
    Optional,
    Protocol,
    runtime_checkable,
    Literal,
    Dict,
    Any,
)

# =========================
# Logging (structured JSON)
# =========================

_LOG = logging.getLogger("oblivionvault.archive.retrieval")
if not _LOG.handlers:
    # Default to INFO with simple stream handler; production can override.
    _LOG.setLevel(logging.INFO)
    h = logging.StreamHandler()
    h.setLevel(logging.INFO)
    fmt = logging.Formatter("%(message)s")
    h.setFormatter(fmt)
    _LOG.addHandler(h)


def _json_log(event: str, **fields: Any) -> None:
    payload = {"ts": time.time(), "event": event, **fields}
    _LOG.info(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))


# =========================
# Domain models & contracts
# =========================

@dataclasses.dataclass(frozen=True, slots=True)
class ArchiveLocator:
    """
    Describes how to find an archived object.

    namespace: logical partition (e.g., tenant/project)
    object_id: immutable identifier (content-id or UUID)
    version: optional version label/number
    backend: preferred backend key (e.g., "local", "s3"). May be overridden by policy.
    path_hint: optional fully qualified path within backend (if pre-resolved)
    size: expected size in bytes (optional; used for validation)
    sha256_hex: optional expected SHA-256 for integrity check
    enc_ctx: optional envelope for crypto provider (e.g., key_id, nonce)
    """
    namespace: str
    object_id: str
    version: Optional[str] = None
    backend: Optional[str] = None
    path_hint: Optional[str] = None
    size: Optional[int] = None
    sha256_hex: Optional[str] = None
    enc_ctx: Optional[Dict[str, Any]] = None


@runtime_checkable
class StorageBackend(Protocol):
    """
    Async storage backend capable of range reads and metadata queries.
    Implementations must be cancellation-safe and not swallow CancelledError.
    """

    name: str

    async def exists(self, path: str) -> bool:
        ...

    async def size(self, path: str) -> int:
        ...

    async def read(
        self, path: str, *, offset: int = 0, length: Optional[int] = None, chunk_size: int = 1024 * 1024
    ) -> AsyncIterator[bytes]:
        """
        Stream bytes from object at `path` starting at `offset` for at most `length` bytes.
        If length is None, read until EOF. Yields chunks of up to chunk_size.
        """
        ...


class CryptoProvider(Protocol):
    """
    Optional crypto layer. Default implementation is identity (no-op).
    """

    name: str

    async def decrypt_stream(
        self, it: AsyncIterator[bytes], *, enc_ctx: Optional[Dict[str, Any]]
    ) -> AsyncIterator[bytes]:
        """
        Given a plaintext or ciphertext stream and context, return plaintext stream.
        Default no-op provider must return `it` unchanged.
        """
        ...


class NoOpCrypto:
    name = "noop"

    async def decrypt_stream(
        self, it: AsyncIterator[bytes], *, enc_ctx: Optional[Dict[str, Any]]
    ) -> AsyncIterator[bytes]:
        async for chunk in it:
            yield chunk


# ===============
# Local FS backend
# ===============

class LocalFileBackend:
    """
    Stdlib-only local filesystem backend with async range-read via thread offloading.
    """

    def __init__(self, root: str | Path, name: str = "local") -> None:
        self._root = Path(root).resolve()
        self.name = name

    def _resolve(self, path: str) -> Path:
        p = (self._root / path.lstrip("/")).resolve()
        if not str(p).startswith(str(self._root)):
            raise SecurityError(f"Path escapes root: {p}")
        return p

    async def exists(self, path: str) -> bool:
        rp = self._resolve(path)
        return await asyncio.to_thread(rp.exists)

    async def size(self, path: str) -> int:
        rp = self._resolve(path)
        if not await asyncio.to_thread(rp.exists):
            raise NotFoundError(f"{rp} does not exist")
        st = await asyncio.to_thread(rp.stat)
        return st.st_size

    async def read(
        self, path: str, *, offset: int = 0, length: Optional[int] = None, chunk_size: int = 1024 * 1024
    ) -> AsyncIterator[bytes]:
        rp = self._resolve(path)
        if not await asyncio.to_thread(rp.exists):
            raise NotFoundError(f"{rp} does not exist")
        if offset < 0:
            raise ValueError("offset must be >= 0")
        if length is not None and length < 0:
            raise ValueError("length must be >= 0")

        def _reader() -> io.BufferedReader:
            f = open(rp, "rb", buffering=0)
            try:
                f.seek(offset)
            except Exception:
                f.close()
                raise
            return f  # caller closes

        f = await asyncio.to_thread(_reader)
        try:
            remaining = length
            while True:
                to_read = chunk_size
                if remaining is not None:
                    if remaining <= 0:
                        break
                    to_read = min(to_read, remaining)
                data = await asyncio.to_thread(f.read, to_read)
                if not data:
                    break
                if remaining is not None:
                    remaining -= len(data)
                yield data
        finally:
            await asyncio.to_thread(f.close)


# ==========================
# Exceptions & failure modes
# ==========================

class RetrievalError(Exception):
    pass


class NotFoundError(RetrievalError):
    pass


class IntegrityError(RetrievalError):
    pass


class SecurityError(RetrievalError):
    pass


class BackendSelectionError(RetrievalError):
    pass


# =======================
# Retry & Circuit-Breaker
# =======================

class CircuitBreaker:
    """
    Minimal, thread-safe enough for asyncio's single-threaded model.
    States: closed → open (after failures) → half_open → closed on success.
    """

    __slots__ = ("_failures", "_state", "_opened_at", "_lock", "failure_threshold", "reset_timeout")

    def __init__(self, failure_threshold: int = 5, reset_timeout: float = 30.0) -> None:
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self._failures = 0
        self._state: Literal["closed", "open", "half_open"] = "closed"
        self._opened_at = 0.0
        self._lock = asyncio.Lock()

    async def allow(self) -> bool:
        async with self._lock:
            now = time.time()
            if self._state == "open":
                if (now - self._opened_at) >= self.reset_timeout:
                    self._state = "half_open"
                    return True
                return False
            return True

    async def record_success(self) -> None:
        async with self._lock:
            self._failures = 0
            self._state = "closed"

    async def record_failure(self) -> None:
        async with self._lock:
            self._failures += 1
            if self._failures >= self.failure_threshold:
                self._state = "open"
                self._opened_at = time.time()


async def _async_retry(
    func,
    *,
    attempts: int = 3,
    base_delay: float = 0.1,
    max_delay: float = 2.0,
    retry_on: tuple[type[Exception], ...] = (OSError, RetrievalError),
    breaker: Optional[CircuitBreaker] = None,
):
    last_exc: Optional[BaseException] = None
    for i in range(1, attempts + 1):
        if breaker is not None:
            allowed = await breaker.allow()
            if not allowed:
                raise RetrievalError("circuit_open")
        try:
            return await func()
        except asyncio.CancelledError:
            raise
        except retry_on as exc:  # type: ignore
            last_exc = exc
            if breaker is not None:
                await breaker.record_failure()
            if i == attempts:
                break
            delay = min(max_delay, base_delay * (2 ** (i - 1)))
            await asyncio.sleep(delay)
        else:
            if breaker is not None:
                await breaker.record_success()
    assert last_exc is not None
    raise last_exc


# =====================
# Integrity & utilities
# =====================

async def _hash_stream(
    it: AsyncIterator[bytes], *, algo: str = "sha256", buf: int = 1024 * 1024
) -> tuple[str, int]:
    if algo != "sha256":
        raise ValueError("Only sha256 is supported in stdlib mode")
    h = hashlib.sha256()
    total = 0
    async for chunk in it:
        h.update(chunk)
        total += len(chunk)
    return h.hexdigest(), total


async def _tee_stream(it: AsyncIterator[bytes]) -> tuple[AsyncIterator[bytes], AsyncIterator[bytes]]:
    """
    Duplicate an async iterator into two identical streams.
    """
    queue: asyncio.Queue[Optional[bytes]] = asyncio.Queue(maxsize=2)

    async def producer():
        try:
            async for chunk in it:
                await queue.put(chunk)
        finally:
            await queue.put(None)

    async def consumer() -> AsyncIterator[bytes]:
        while True:
            item = await queue.get()
            if item is None:
                break
            yield item

    asyncio.create_task(producer())
    return consumer(), consumer()


async def _write_atomic(path: Path, it: AsyncIterator[bytes], *, mode: int = 0o640) -> int:
    """
    Write stream to temp file and atomically replace target. Returns bytes written.
    """
    path = path.resolve()
    tmp = path.with_suffix(path.suffix + ".tmp-" + str(os.getpid()) + "-" + str(int(time.time() * 1000)))
    written = 0

    def _open_tmp() -> io.BufferedWriter:
        tmp.parent.mkdir(parents=True, exist_ok=True)
        f = open(tmp, "wb", buffering=0)
        os.chmod(f.fileno(), mode)
        return f

    f = await asyncio.to_thread(_open_tmp)
    try:
        async for chunk in it:
            await asyncio.to_thread(f.write, chunk)
            written += len(chunk)
    except Exception:
        with contextlib.suppress(Exception):
            await asyncio.to_thread(f.close)
        with contextlib.suppress(Exception):
            await asyncio.to_thread(tmp.unlink)
        raise
    else:
        await asyncio.to_thread(f.flush)
        os.fsync(f.fileno())
        await asyncio.to_thread(f.close)
        await asyncio.to_thread(os.replace, tmp, path)
        return written


# =====================
# Retrieval Orchestrator
# =====================

@dataclasses.dataclass(slots=True)
class RetrievalConfig:
    default_backend: str = "local"
    read_chunk_size: int = 1024 * 1024
    hash_algorithm: str = "sha256"
    max_attempts: int = 3
    base_delay: float = 0.05
    max_delay: float = 0.5
    op_timeout_s: float = 120.0
    cb_failure_threshold: int = 5
    cb_reset_timeout_s: float = 30.0
    verify_integrity: bool = True


class ArchiveRetrievalService:
    """
    High-level retrieval with integrity, retries, timeouts, and observability.
    """

    def __init__(
        self,
        backends: Dict[str, StorageBackend],
        crypto: Optional[CryptoProvider] = None,
        config: Optional[RetrievalConfig] = None,
        loop: Optional[AbstractEventLoop] = None,
    ) -> None:
        if not backends:
            raise ValueError("at least one backend required")
        self._backends = backends
        self._crypto = crypto or NoOpCrypto()
        self._cfg = config or RetrievalConfig()
        self._loop = loop or asyncio.get_event_loop()
        self._breaker = CircuitBreaker(
            failure_threshold=self._cfg.cb_failure_threshold,
            reset_timeout=self._cfg.cb_reset_timeout_s,
        )
        # Metadata cache (best-effort)
        self._meta_cache: Dict[str, int] = {}

    def _select_backend(self, loc: ArchiveLocator) -> tuple[StorageBackend, str]:
        name = (loc.backend or self._cfg.default_backend).strip()
        if name not in self._backends:
            raise BackendSelectionError(f"backend '{name}' not configured")
        backend = self._backends[name]
        # Path resolution strategy: prefer explicit hint, else derive canonical path.
        path = loc.path_hint or self._derive_path(loc)
        return backend, path

    @staticmethod
    def _derive_path(loc: ArchiveLocator) -> str:
        ver = f"/v={loc.version}" if loc.version else ""
        # Canonical, filesystem-friendly layout
        return f"{loc.namespace}/{loc.object_id}{ver}"

    async def head(self, loc: ArchiveLocator) -> dict[str, Any]:
        backend, path = self._select_backend(loc)

        async def _do():
            exists = await backend.exists(path)
            if not exists:
                raise NotFoundError(f"{backend.name}:{path} not found")
            size = await backend.size(path)
            self._meta_cache[f"{backend.name}:{path}"] = size
            return {"backend": backend.name, "path": path, "size": size}

        _json_log("retrieve.head.start", backend=backend.name, path=path, locator=dataclasses.asdict(loc))
        try:
            res = await asyncio.wait_for(
                _async_retry(
                    _do,
                    attempts=self._cfg.max_attempts,
                    base_delay=self._cfg.base_delay,
                    max_delay=self._cfg.max_delay,
                    breaker=self._breaker,
                ),
                timeout=self._cfg.op_timeout_s,
            )
            _json_log("retrieve.head.ok", **res)
            return res
        except Exception as e:
            _json_log("retrieve.head.err", error=type(e).__name__, msg=str(e))
            raise

    async def _raw_stream(
        self, backend: StorageBackend, path: str, *, offset: int, length: Optional[int]
    ) -> AsyncIterator[bytes]:
        async def _do() -> AsyncIterator[bytes]:
            return backend.read(
                path,
                offset=offset,
                length=length,
                chunk_size=self._cfg.read_chunk_size,
            )

        # We need to flatten `AsyncIterator[bytes]` returned inside retry wrapper.
        # Retry here wraps the *opening* of the stream (first await); subsequent read errors
        # will bubble up to the consumer and are not retried mid-stream (intentional).
        stream: AsyncIterator[bytes] = await _async_retry(
            _do,
            attempts=self._cfg.max_attempts,
            base_delay=self._cfg.base_delay,
            max_delay=self._cfg.max_delay,
            breaker=self._breaker,
        )
        async for chunk in stream:
            yield chunk

    async def _verified_stream(
        self,
        loc: ArchiveLocator,
        *,
        offset: int = 0,
        length: Optional[int] = None,
    ) -> AsyncIterator[bytes]:
        backend, path = self._select_backend(loc)
        _json_log(
            "retrieve.stream.start",
            backend=backend.name,
            path=path,
            offset=offset,
            length=length,
            locator=dataclasses.asdict(loc),
        )

        raw_it = self._raw_stream(backend, path, offset=offset, length=length)

        # Optional decryption (no-op by default)
        dec_it = self._crypto.decrypt_stream(raw_it, enc_ctx=loc.enc_ctx)

        if not (self._cfg.verify_integrity and loc.sha256_hex and offset == 0 and length is None):
            # Integrity check disabled or partial read; just pass-through
            async for chunk in dec_it:
                yield chunk
            _json_log("retrieve.stream.ok", backend=backend.name, path=path, verified=False)
            return

        # Full-object verification
        stream_a, stream_b = await _tee_stream(dec_it)

        async def _hash_task() -> tuple[str, int]:
            return await _hash_stream(stream_b, algo=self._cfg.hash_algorithm)

        # Hash in background while yielding to caller
        hash_fut = asyncio.create_task(_hash_task())

        async for chunk in stream_a:
            yield chunk

        # Finalize
        got_hex, total = await hash_fut
        exp_hex = loc.sha256_hex.lower()
        ok = (got_hex.lower() == exp_hex) and ((loc.size is None) or (loc.size == total))
        if not ok:
            _json_log(
                "retrieve.stream.integrity_mismatch",
                expected_sha256=exp_hex,
                got_sha256=got_hex,
                expected_size=loc.size,
                got_size=total,
            )
            raise IntegrityError("sha256_mismatch_or_size_mismatch")
        _json_log(
            "retrieve.stream.ok",
            backend=backend.name,
            path=path,
            verified=True,
            bytes=total,
            sha256=got_hex,
        )

    async def stream(
        self, loc: ArchiveLocator, *, offset: int = 0, length: Optional[int] = None
    ) -> AsyncIterator[bytes]:
        """
        Public streaming API with timeout envelope.
        """
        it = self._verified_stream(loc, offset=offset, length=length)
        # Enforce operation timeout by chunk — cancels on stall.
        start = time.time()
        try:
            async for chunk in _timeout_iter(it, per_chunk_timeout=self._cfg.op_timeout_s):
                yield chunk
        finally:
            _json_log("retrieve.stream.close", elapsed_s=round(time.time() - start, 3))

    async def to_file(
        self,
        loc: ArchiveLocator,
        dest: str | Path,
        *,
        overwrite: bool = False,
        file_mode: int = 0o640,
    ) -> dict[str, Any]:
        """
        Retrieve object and write atomically to `dest`. Returns result dict.
        """
        dest = Path(dest).resolve()
        if dest.exists() and not overwrite:
            raise RetrievalError(f"destination exists: {dest}")

        backend, path = self._select_backend(loc)
        _json_log("retrieve.to_file.start", backend=backend.name, path=path, dest=str(dest))

        async def _do():
            stream = self._verified_stream(loc)
            written = await _write_atomic(dest, stream, mode=file_mode)
            return written

        try:
            bytes_written = await asyncio.wait_for(
                _async_retry(
                    _do,
                    attempts=self._cfg.max_attempts,
                    base_delay=self._cfg.base_delay,
                    max_delay=self._cfg.max_delay,
                    breaker=self._breaker,
                ),
                timeout=max(self._cfg.op_timeout_s, 10.0),
            )
        except Exception as e:
            _json_log("retrieve.to_file.err", error=type(e).__name__, msg=str(e))
            raise
        else:
            _json_log(
                "retrieve.to_file.ok",
                backend=backend.name,
                path=path,
                dest=str(dest),
                bytes=bytes_written,
            )
            return {"dest": str(dest), "bytes": bytes_written, "backend": backend.name, "path": path}

    async def read_bytes(self, loc: ArchiveLocator, *, max_bytes: Optional[int] = None) -> bytes:
        """
        Convenience helper: read into memory (beware large objects).
        """
        buf = bytearray()
        async for chunk in self.stream(loc, offset=0, length=max_bytes):
            buf.extend(chunk)
            if max_bytes is not None and len(buf) >= max_bytes:
                break
        return bytes(buf)


# =====================
# Timeout helper
# =====================

async def _timeout_iter(it: AsyncIterator[bytes], *, per_chunk_timeout: float) -> AsyncIterator[bytes]:
    """
    Enforces timeout for each chunk retrieval to prevent silent stalls.
    """
    ait = it.__aiter__()
    while True:
        try:
            chunk = await asyncio.wait_for(ait.__anext__(), timeout=per_chunk_timeout)
        except StopAsyncIteration:
            break
        yield chunk


# =====================
# Example factory (DI)
# =====================

def build_default_retrieval_service(local_root: str | Path) -> ArchiveRetrievalService:
    """
    Construct a production-ready service with a local backend and no-op crypto.
    Extend by injecting additional backends (e.g., S3/IPFS) in your composition root.
    """
    backends: Dict[str, StorageBackend] = {
        "local": LocalFileBackend(local_root, name="local"),
    }
    cfg = RetrievalConfig()
    return ArchiveRetrievalService(backends=backends, crypto=NoOpCrypto(), config=cfg)


# =====================
# __all__
# =====================

__all__ = [
    "ArchiveLocator",
    "StorageBackend",
    "CryptoProvider",
    "NoOpCrypto",
    "LocalFileBackend",
    "RetrievalConfig",
    "ArchiveRetrievalService",
    "NotFoundError",
    "IntegrityError",
    "RetrievalError",
    "SecurityError",
    "BackendSelectionError",
    "build_default_retrieval_service",
]
