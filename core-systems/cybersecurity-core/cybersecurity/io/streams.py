# file: cybersecurity-core/cybersecurity/io/streams.py
"""
Промышленный модуль потокового ввода-вывода.

Возможности:
- Унифицированное асинхронное чтение из: Path/str (файл), bytes/bytearray/memoryview,
  sync IO (BinaryIO), async-итераторов (AsyncIterator[bytes]) и sync-итераторов (Iterator[bytes]).
- Унифицированная запись в: Path/str (файл), sync IO (BinaryIO), async sink (с методом async write()).
- On-the-fly хеширование: SHA-256, SHA-1, MD5; опциональная проверка ожидаемого хеша.
- Ограничение скорости (token bucket), учёт времени и прогресса.
- Gzip-компрессия/декомпрессия потоков без буферизации целиком.
- Таймаут на общий прогон и корректное освобождение ресурсов.
- Tee-передача в несколько приёмников.
- Без внешних зависимостей. Python 3.10+.

Применение (пример):
    from pathlib import Path
    from cybersecurity.io.streams import stream_copy, StreamCopyResult

    async def main():
        res = await stream_copy(
            source=Path("input.bin"),
            sink=Path("output.bin"),
            chunk_size=128*1024,
            expected_sha256="...optional hex...",
            rate_limit_bps=10*1024*1024,  # 10 MiB/s
            gzip_compress=False,
            gzip_decompress=False,
            timeout=120,
        )
        print(res.bytes_written, res.sha256)

Автор: Aethernova / cybersecurity-core
Лицензия: Apache-2.0
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import os
import time
import zlib
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    BinaryIO,
    Callable,
    Iterator,
    Optional,
    Protocol,
    Union,
)

# ------------------------------- Константы -----------------------------------

DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KiB
DEFAULT_GZIP_LEVEL = 6

# ------------------------------- Исключения ----------------------------------

class StreamError(Exception):
    """Общее исключение модуля потоков."""


class IntegrityError(StreamError):
    """Нарушение целостности: хеш не совпал."""


class RateLimitExceeded(StreamError):
    """Ограничение скорости нарушено (внутреннее)."""


class StreamTimeout(StreamError):
    """Истек общий таймаут операции."""


# ------------------------------- Протоколы -----------------------------------

class AsyncByteSink(Protocol):
    async def write(self, data: bytes) -> None: ...
    async def aclose(self) -> None: ...


# ------------------------------- Хеши ----------------------------------------

@dataclass
class RunningHashes:
    sha256: hashlib._hashlib.HASH
    sha1: hashlib._hashlib.HASH
    md5: hashlib._hashlib.HASH

    @classmethod
    def create(cls) -> "RunningHashes":
        return cls(hashlib.sha256(), hashlib.sha1(), hashlib.md5())

    def update(self, data: bytes) -> None:
        self.sha256.update(data)
        self.sha1.update(data)
        self.md5.update(data)

    @property
    def sha256_hex(self) -> str:
        return self.sha256.hexdigest()

    @property
    def sha1_hex(self) -> str:
        return self.sha1.hexdigest()

    @property
    def md5_hex(self) -> str:
        return self.md5.hexdigest()


# ------------------------------- Rate Limiter --------------------------------

class _TokenBucket:
    """
    Простой token-bucket ограничитель скорости (байт/сек).
    Потокобезопасность на уровне одного loop (одна корутина на копирование).
    """
    def __init__(self, rate_bps: int) -> None:
        self.rate = max(1, int(rate_bps))
        self.capacity = float(self.rate)
        self.tokens = float(self.capacity)
        self.ts = time.monotonic()

    async def consume(self, n: int) -> None:
        if n <= 0:
            return
        while True:
            now = time.monotonic()
            elapsed = now - self.ts
            self.ts = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            if self.tokens >= n:
                self.tokens -= n
                return
            missing = n - self.tokens
            # время, необходимое для накопления недостающих токенов
            await asyncio.sleep(missing / self.rate + 0.001)


# ------------------------------- Адаптеры источников -------------------------

async def _aiter_from_path(path: Path, chunk_size: int) -> AsyncIterator[bytes]:
    def _open_and_read_chunks(p: Path, csz: int):
        with p.open("rb") as f:
            while True:
                b = f.read(csz)
                if not b:
                    break
                yield b

    # Итерируем чтение в thread, передавая через локальную очередъ
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[Optional[bytes]] = asyncio.Queue(maxsize=8)

    def _producer():
        try:
            for chunk in _open_and_read_chunks(path, chunk_size):
                loop.call_soon_threadsafe(queue.put_nowait, chunk)
        except Exception as e:
            loop.call_soon_threadsafe(queue.put_nowait, None)
            raise e
        else:
            loop.call_soon_threadsafe(queue.put_nowait, None)

    await asyncio.to_thread(_producer)
    # Первый put произойдёт синхронно в to_thread, далее потребляем
    while True:
        item = await queue.get()
        if item is None:
            break
        yield item


async def _aiter_from_binaryio(bio: BinaryIO, chunk_size: int) -> AsyncIterator[bytes]:
    while True:
        chunk = await asyncio.to_thread(bio.read, chunk_size)
        if not chunk:
            break
        yield chunk


async def _aiter_from_iter(it: Iterator[bytes]) -> AsyncIterator[bytes]:
    # Переносим итерацию в thread, передаём через очередь
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[Optional[bytes]] = asyncio.Queue(maxsize=8)

    def _producer():
        try:
            for chunk in it:
                if not isinstance(chunk, (bytes, bytearray, memoryview)):
                    raise StreamError("Iterator must yield bytes-like")
                loop.call_soon_threadsafe(queue.put_nowait, bytes(chunk))
        except Exception as e:
            loop.call_soon_threadsafe(queue.put_nowait, None)
            raise e
        else:
            loop.call_soon_threadsafe(queue.put_nowait, None)

    await asyncio.to_thread(_producer)
    while True:
        item = await queue.get()
        if item is None:
            break
        yield item


async def aiter_bytes(
    source: Union[
        Path, str, bytes, bytearray, memoryview,
        BinaryIO, AsyncIterator[bytes], Iterator[bytes]
    ],
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> AsyncIterator[bytes]:
    """
    Унифицированный асинхронный итератор байтовых чанков из разных источников.
    """
    if isinstance(source, (bytes, bytearray, memoryview)):
        yield bytes(source)
        return

    if isinstance(source, (str, Path)):
        return (_ for _ in [])  # тип-хинт трюк; ниже фактический yield
    # fall through to real generator below


    if isinstance(source, (str, Path)):
        path = Path(source)
        async for chunk in _aiter_from_path(path, chunk_size):
            yield chunk
        return

    if isinstance(source, io.BufferedReader) or isinstance(source, io.RawIOBase):
        async for chunk in _aiter_from_binaryio(source, chunk_size):
            yield chunk
        return

    if hasattr(source, "__anext__"):
        async for chunk in source:  # type: ignore[func-returns-value]
            if not isinstance(chunk, (bytes, bytearray, memoryview)):
                raise StreamError("AsyncIterator must yield bytes-like")
            yield bytes(chunk)
        return

    if hasattr(source, "__iter__"):
        async for chunk in _aiter_from_iter(source):  # type: ignore[arg-type]
            yield chunk
        return

    raise StreamError(f"Unsupported source type: {type(source)!r}")


# ------------------------------- Адаптеры приёмников -------------------------

class _FileSink(AsyncByteSink):
    def __init__(self, path: Path) -> None:
        self._path = path
        self._f: Optional[BinaryIO] = None

    async def _ensure_open(self) -> None:
        if self._f is None:
            self._f = await asyncio.to_thread(self._path.open, "wb")

    async def write(self, data: bytes) -> None:
        await self._ensure_open()
        assert self._f
        await asyncio.to_thread(self._f.write, data)

    async def aclose(self) -> None:
        if self._f is not None:
            await asyncio.to_thread(self._f.flush)
            await asyncio.to_thread(self._f.close)
            self._f = None


class _BinaryIOSink(AsyncByteSink):
    def __init__(self, bio: BinaryIO) -> None:
        self._bio = bio

    async def write(self, data: bytes) -> None:
        await asyncio.to_thread(self._bio.write, data)

    async def aclose(self) -> None:
        try:
            await asyncio.to_thread(self._bio.flush)
        except Exception:
            pass


class _CallableSink(AsyncByteSink):
    def __init__(self, fn: Union[Callable[[bytes], Any], Callable[[bytes], Awaitable[Any]]]) -> None:
        self._fn = fn
        self._is_async = asyncio.iscoroutinefunction(fn)  # type: ignore[arg-type]

    async def write(self, data: bytes) -> None:
        if self._is_async:
            await self._fn(data)  # type: ignore[misc]
        else:
            await asyncio.to_thread(self._fn, data)  # type: ignore[misc]

    async def aclose(self) -> None:
        return


@asynccontextmanager
async def open_sink(
    sink: Union[Path, str, BinaryIO, AsyncByteSink, Callable[[bytes], Any], Callable[[bytes], Awaitable[Any]]]
) -> AsyncIterator[AsyncByteSink]:
    if isinstance(sink, (str, Path)):
        s = _FileSink(Path(sink))
        try:
            yield s
        finally:
            await s.aclose()
        return

    if isinstance(sink, io.BufferedWriter) or isinstance(sink, io.RawIOBase):
        s = _BinaryIOSink(sink)  # type: ignore[arg-type]
        try:
            yield s
        finally:
            await s.aclose()
        return

    if hasattr(sink, "write") and hasattr(sink, "aclose"):
        # Похоже на AsyncByteSink
        yield sink  # type: ignore[misc]
        return

    if callable(sink):
        s = _CallableSink(sink)  # type: ignore[arg-type]
        try:
            yield s
        finally:
            await s.aclose()
        return

    raise StreamError(f"Unsupported sink type: {type(sink)!r}")


# ------------------------------- Gzip конвейеры ------------------------------

class _GzipCompressor:
    def __init__(self, level: int = DEFAULT_GZIP_LEVEL) -> None:
        self._co = zlib.compressobj(level, zlib.DEFLATED, zlib.MAX_WBITS | 16)

    def compress(self, data: bytes) -> bytes:
        return self._co.compress(data)

    def flush(self) -> bytes:
        return self._co.flush()


class _GzipDecompressor:
    def __init__(self) -> None:
        self._do = zlib.decompressobj(wbits=zlib.MAX_WBITS | 16)

    def decompress(self, data: bytes) -> bytes:
        return self._do.decompress(data)

    def flush(self) -> bytes:
        return self._do.flush()


# ------------------------------- Прогресс ------------------------------------

@dataclass
class Progress:
    started_at: float
    bytes_done: int
    bytes_total: Optional[int]
    elapsed: float
    speed_bps: float


# ------------------------------- Результат -----------------------------------

@dataclass
class StreamCopyResult:
    bytes_written: int
    duration_seconds: float
    sha256: str
    sha1: str
    md5: str
    gzipped: bool
    gunzipped: bool
    rate_limited: bool


# ------------------------------- Основные API --------------------------------

async def stream_copy(
    *,
    source: Union[
        Path, str, bytes, bytearray, memoryview,
        BinaryIO, AsyncIterator[bytes], Iterator[bytes]
    ],
    sink: Union[Path, str, BinaryIO, AsyncByteSink, Callable[[bytes], Any], Callable[[bytes], Awaitable[Any]]],
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    rate_limit_bps: Optional[int] = None,
    expected_sha256: Optional[str] = None,
    gzip_compress: bool = False,
    gzip_decompress: bool = False,
    gzip_level: int = DEFAULT_GZIP_LEVEL,
    progress_cb: Optional[Callable[[Progress], Any]] = None,
    timeout: Optional[float] = None,
    total_size_hint: Optional[int] = None,
) -> StreamCopyResult:
    """
    Копирует поток из source в sink с опциональными фичами:
      - ограничение скорости,
      - gzip-компрессия/декомпрессия,
      - подсчёт и проверка хеша,
      - прогресс-колбэк,
      - общий таймаут выполнения.
    """
    start = time.monotonic()
    hashes = RunningHashes.create()
    limiter = _TokenBucket(rate_limit_bps) if rate_limit_bps else None
    rate_limited = False

    comp = _GzipCompressor(gzip_level) if gzip_compress else None
    decomp = _GzipDecompressor() if gzip_decompress else None
    bytes_written = 0

    async def _do_copy() -> None:
        nonlocal bytes_written, rate_limited
        async with open_sink(sink) as s:
            async for chunk in aiter_bytes(source, chunk_size=chunk_size):
                if decomp:
                    out = decomp.decompress(chunk)
                    if out:
                        if limiter:
                            await limiter.consume(len(out))
                            rate_limited = True
                        hashes.update(out)
                        await s.write(out)
                        bytes_written += len(out)
                elif comp:
                    maybe = comp.compress(chunk)
                    if maybe:
                        if limiter:
                            await limiter.consume(len(maybe))
                            rate_limited = True
                        hashes.update(maybe)
                        await s.write(maybe)
                        bytes_written += len(maybe)
                else:
                    if limiter:
                        await limiter.consume(len(chunk))
                        rate_limited = True
                    hashes.update(chunk)
                    await s.write(chunk)
                    bytes_written += len(chunk)

                if progress_cb:
                    now = time.monotonic()
                    elapsed = max(1e-6, now - start)
                    speed = bytes_written / elapsed
                    try:
                        progress_cb(Progress(started_at=start, bytes_done=bytes_written,
                                             bytes_total=total_size_hint, elapsed=elapsed, speed_bps=speed))
                    except Exception:
                        # Прогресс не должен ронять копирование
                        pass

            # Финальные хвосты gzip
            if decomp:
                tail = decomp.flush()
                if tail:
                    if limiter:
                        await limiter.consume(len(tail))
                        rate_limited = True
                    hashes.update(tail)
                    await s.write(tail)
                    bytes_written += len(tail)
            if comp:
                tail = comp.flush()
                if tail:
                    if limiter:
                        await limiter.consume(len(tail))
                        rate_limited = True
                    hashes.update(tail)
                    await s.write(tail)
                    bytes_written += len(tail)

            await s.aclose()

    if timeout is not None:
        try:
            await asyncio.wait_for(_do_copy(), timeout=timeout)
        except asyncio.TimeoutError as e:
            raise StreamTimeout(f"Copy timed out after {timeout} seconds") from e
    else:
        await _do_copy()

    # Проверка хеша (если была gzip-компрессия, хеш относится к записанным данным)
    if expected_sha256 and hashes.sha256_hex.lower() != expected_sha256.lower():
        raise IntegrityError("SHA-256 mismatch")

    duration = max(0.0, time.monotonic() - start)
    return StreamCopyResult(
        bytes_written=bytes_written,
        duration_seconds=duration,
        sha256=hashes.sha256_hex,
        sha1=hashes.sha1_hex,
        md5=hashes.md5_hex,
        gzipped=bool(comp),
        gunzipped=bool(decomp),
        rate_limited=rate_limited,
    )


async def stream_tee(
    source: Union[
        Path, str, bytes, bytearray, memoryview,
        BinaryIO, AsyncIterator[bytes], Iterator[bytes]
    ],
    sinks: list[Union[Path, str, BinaryIO, AsyncByteSink, Callable[[bytes], Any], Callable[[bytes], Awaitable[Any]]]],
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    rate_limit_bps: Optional[int] = None,
    timeout: Optional[float] = None,
) -> list[StreamCopyResult]:
    """
    Разветвляет один поток на несколько приёмников (fan-out).
    Ограничение скорости применяется к суммарному исходящему потоку.
    """
    start = time.monotonic()
    limiter = _TokenBucket(rate_limit_bps) if rate_limit_bps else None
    hashes = [RunningHashes.create() for _ in sinks]
    bytes_written = [0 for _ in sinks]
    sinks_ctx: list[AsyncByteSink] = []

    @asynccontextmanager
    async def _open_all():
        try:
            for sk in sinks:
                cm = open_sink(sk)
                s = await cm.__aenter__()
                sinks_ctx.append(s)
            yield
        finally:
            # закрываем все даже если были ошибки
            for s in sinks_ctx:
                try:
                    await s.aclose()
                except Exception:
                    pass

    async def _do() -> None:
        async with _open_all():
            async for chunk in aiter_bytes(source, chunk_size=chunk_size):
                if limiter:
                    await limiter.consume(len(chunk))
                # Запись параллельно
                await asyncio.gather(*[sinks_ctx[i].write(chunk) for i in range(len(sinks_ctx))])
                for i, h in enumerate(hashes):
                    h.update(chunk)
                    bytes_written[i] += len(chunk)

    if timeout is not None:
        try:
            await asyncio.wait_for(_do(), timeout=timeout)
        except asyncio.TimeoutError as e:
            raise StreamTimeout(f"Tee timed out after {timeout} seconds") from e
    else:
        await _do()

    dur = max(0.0, time.monotonic() - start)
    results: list[StreamCopyResult] = []
    for i, h in enumerate(hashes):
        results.append(
            StreamCopyResult(
                bytes_written=bytes_written[i],
                duration_seconds=dur,
                sha256=h.sha256_hex,
                sha1=h.sha1_hex,
                md5=h.md5_hex,
                gzipped=False,
                gunzipped=False,
                rate_limited=bool(limiter),
            )
        )
    return results


# ------------------------------- Вспомогательные -----------------------------

def human_bps(bps: float) -> str:
    units = ["B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"]
    v = float(bps)
    i = 0
    while v >= 1024.0 and i < len(units) - 1:
        v /= 1024.0
        i += 1
    return f"{v:.2f} {units[i]}"


async def read_all(source: Union[Path, str, BinaryIO, AsyncIterator[bytes], Iterator[bytes], bytes], limit: int | None = None) -> bytes:
    """
    Считывает весь источник в память (осторожно: для небольших объёмов).
    limit — максимальный допустимый размер; при превышении — StreamError.
    """
    buf = bytearray()
    async for chunk in aiter_bytes(source, chunk_size=DEFAULT_CHUNK_SIZE):
        buf.extend(chunk)
        if limit is not None and len(buf) > limit:
            raise StreamError("read_all: size exceeds limit")
    return bytes(buf)
