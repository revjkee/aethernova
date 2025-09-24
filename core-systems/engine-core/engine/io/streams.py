# engine-core/engine/io/streams.py
"""
Industrial-grade streaming primitives (sync/async), framing, rate limiting, and multiplexing.

Features:
- Sync/Async readable/writable interfaces with backpressure semantics
- In-memory async duplex pipe with bounded ring buffer
- Token-bucket rate limiter (async)
- Length-prefixed framing with varint, optional CRC32 + per-frame zlib compression
- Stream mux/demux by logical channel id
- Buffered wrappers (reader/writer) for efficiency
- Deterministic varint codec; safe timeouts; structured errors
- Telemetry hooks (callbacks) for bytes/frames/latency

No external dependencies. Python 3.10+.
"""

from __future__ import annotations

import asyncio
import io
import struct
import time
import zlib
from dataclasses import dataclass
from typing import AsyncIterator, Awaitable, Callable, Deque, Dict, Iterable, List, Optional, Tuple, Union
import collections

# =========================
# Errors
# =========================

class StreamError(Exception):
    pass

class StreamClosed(StreamError):
    pass

class StreamTimeout(StreamError):
    pass

class StreamBackpressure(StreamError):
    pass

class FrameError(StreamError):
    pass

# =========================
# Varint (protobuf-like, unsigned)
# =========================

def uvarint_encode(n: int) -> bytes:
    if n < 0:
        raise ValueError("uvarint must be >= 0")
    out = bytearray()
    x = n
    while True:
        b = x & 0x7F
        x >>= 7
        if x:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)

def uvarint_decode_from(read_exact: Callable[[int], bytes]) -> int:
    shift = 0
    result = 0
    for _ in range(10):  # up to 64-bit
        b = read_exact(1)[0]
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return result
        shift += 7
    raise FrameError("uvarint too long")

async def auvarint_decode_from(aread_exact: Callable[[int], Awaitable[bytes]]) -> int:
    shift = 0
    result = 0
    for _ in range(10):
        b = (await aread_exact(1))[0]
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return result
        shift += 7
    raise FrameError("uvarint too long")

# =========================
# Rate limiter (async token bucket)
# =========================

class TokenBucket:
    def __init__(self, rate_per_s: float, burst: float) -> None:
        self.rate = float(max(0.0, rate_per_s))
        self.burst = float(max(1.0, burst))
        self._tokens = self.burst
        self._last = time.monotonic()
        self._cv = asyncio.Condition()

    def _refill(self) -> None:
        now = time.monotonic()
        dt = now - self._last
        if dt > 0:
            self._tokens = min(self.burst, self._tokens + dt * self.rate)
            self._last = now

    async def acquire(self, amount: float = 1.0, timeout: Optional[float] = None) -> None:
        deadline = None if timeout is None else (time.monotonic() + timeout)
        async with self._cv:
            while True:
                self._refill()
                if self._tokens >= amount:
                    self._tokens -= amount
                    return
                if deadline is not None and time.monotonic() >= deadline:
                    raise StreamTimeout("rate limiter timeout")
                await self._cv.wait_for(lambda: False, timeout=0.02)

    def release(self, amount: float = 1.0) -> None:
        async def _notify():
            async with self._cv:
                self._tokens = min(self.burst, self._tokens + amount)
                self._cv.notify_all()
        try:
            asyncio.get_running_loop().create_task(_notify())
        except RuntimeError:
            pass

# =========================
# Telemetry hook
# =========================

TelemetryHook = Callable[[str, Dict[str, str], Dict[str, float]], None]

def _telemetry(tel: Optional[TelemetryHook], name: str, tags: Dict[str, str] | None = None, fields: Dict[str, float] | None = None) -> None:
    if not tel:
        return
    try:
        tel(name, tags or {}, fields or {})
    except Exception:
        pass

# =========================
# Sync basic adapters (files)
# =========================

class SyncReadable:
    def read(self, n: int) -> bytes:  # may return fewer than n
        raise NotImplementedError
    def readexactly(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.read(n - len(buf))
            if not chunk:
                raise StreamClosed("EOF while readexactly")
            buf += chunk
        return bytes(buf)
    def close(self) -> None:
        raise NotImplementedError

class SyncWritable:
    def write(self, b: bytes) -> int:
        raise NotImplementedError
    def flush(self) -> None:
        pass
    def close(self) -> None:
        raise NotImplementedError

class FileReadable(SyncReadable):
    def __init__(self, f: io.BufferedReader) -> None:
        self._f = f
    def read(self, n: int) -> bytes:
        return self._f.read(n)
    def close(self) -> None:
        try: self._f.close()
        except Exception: pass

class FileWritable(SyncWritable):
    def __init__(self, f: io.BufferedWriter) -> None:
        self._f = f
    def write(self, b: bytes) -> int:
        return self._f.write(b)
    def flush(self) -> None:
        self._f.flush()
    def close(self) -> None:
        try: self._f.close()
        except Exception: pass

# =========================
# Async in-memory duplex pipe with backpressure
# =========================

class AsyncReadable:
    async def read(self, n: int) -> bytes:
        raise NotImplementedError
    async def readexactly(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = await self.read(n - len(buf))
            if not chunk:
                raise StreamClosed("EOF while readexactly")
            buf += chunk
        return bytes(buf)
    async def aclose(self) -> None:
        raise NotImplementedError

class AsyncWritable:
    async def write(self, b: bytes) -> int:
        raise NotImplementedError
    async def drain(self) -> None:
        pass
    async def aclose(self) -> None:
        raise NotImplementedError

class InMemoryDuplex(AsyncReadable, AsyncWritable):
    """
    Async in-memory bounded pipe (single writer, single reader recommended).
    Backpressure via capacity bound; supports half-close.
    """
    def __init__(self, capacity: int = 256 * 1024) -> None:
        self._buf = bytearray()
        self._cap = int(max(1024, capacity))
        self._cv = asyncio.Condition()
        self._closed_read = False
        self._closed_write = False

    async def write(self, b: bytes) -> int:
        if self._closed_write:
            raise StreamClosed("write on closed pipe")
        off = 0
        async with self._cv:
            while off < len(b):
                while len(self._buf) >= self._cap:
                    if self._closed_read:
                        raise StreamClosed("reader closed")
                    await self._cv.wait()
                can = min(len(b) - off, self._cap - len(self._buf))
                self._buf += b[off:off+can]
                off += can
                self._cv.notify_all()
        return off

    async def read(self, n: int) -> bytes:
        async with self._cv:
            while not self._buf and not self._closed_write:
                await self._cv.wait()
            if not self._buf and self._closed_write:
                return b""
            out = self._buf[:n]
            del self._buf[:n]
            self._cv.notify_all()
            return bytes(out)

    async def drain(self) -> None:
        # For symmetry with socket-like interfaces
        await asyncio.sleep(0)

    async def aclose(self) -> None:
        async with self._cv:
            self._closed_write = True
            self._closed_read = True
            self._cv.notify_all()

    async def close_write(self) -> None:
        async with self._cv:
            self._closed_write = True
            self._cv.notify_all()

    async def close_read(self) -> None:
        async with self._cv:
            self._closed_read = True
            self._cv.notify_all()

# =========================
# Buffered wrappers (async)
# =========================

class BufferedAsyncReader(AsyncReadable):
    def __init__(self, base: AsyncReadable, bufsize: int = 64 * 1024) -> None:
        self._b = base
        self._buf = bytearray()
        self._bs = int(max(1024, bufsize))

    async def read(self, n: int) -> bytes:
        if len(self._buf) >= n:
            out = self._buf[:n]
            del self._buf[:n]
            return bytes(out)
        # refill
        chunk = await self._b.read(self._bs)
        if not chunk:
            # flush remainder
            out = bytes(self._buf)
            self._buf.clear()
            return out
        self._buf += chunk
        return await self.read(n)

    async def readexactly(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = await self._b.read(self._bs)
            if not chunk:
                if len(self._buf) < n:
                    raise StreamClosed("EOF while readexactly")
                break
            self._buf += chunk
        out = self._buf[:n]
        del self._buf[:n]
        return bytes(out)

    async def aclose(self) -> None:
        await self._b.aclose()

class BufferedAsyncWriter(AsyncWritable):
    def __init__(self, base: AsyncWritable, bufsize: int = 64 * 1024) -> None:
        self._b = base
        self._buf = bytearray()
        self._bs = int(max(1024, bufsize))

    async def write(self, b: bytes) -> int:
        self._buf += b
        if len(self._buf) >= self._bs:
            await self._b.write(self._buf)
            self._buf.clear()
        return len(b)

    async def flush(self) -> None:
        if self._buf:
            await self._b.write(self._buf)
            self._buf.clear()
        await self._b.drain()

    async def drain(self) -> None:
        await self.flush()

    async def aclose(self) -> None:
        await self.flush()
        await self._b.aclose()

# =========================
# Framed async stream (length-prefixed frames)
# =========================

@dataclass
class FrameConfig:
    enable_crc32: bool = True
    enable_compress: bool = False     # zlib per-frame if payload compresses smaller
    max_frame_size: int = 8 * 1024 * 1024
    # telemetry
    telemetry: Optional[TelemetryHook] = None

class FramedAsyncWriter:
    """
    Writer of frames: [len uvarint][flags u8][payload or zlib(payload)][optional crc32 u32]
    flags: bit0=compressed
    """
    def __init__(self, base: AsyncWritable, cfg: FrameConfig = FrameConfig(), limiter: Optional[TokenBucket] = None) -> None:
        self._b = base
        self._cfg = cfg
        self._limiter = limiter

    async def write_frame(self, payload: bytes) -> None:
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise TypeError("payload must be bytes-like")
        body = bytes(payload)
        flags = 0
        if self._cfg.enable_compress:
            comp = zlib.compress(body, level=6)
            if len(comp) < len(body):
                body = comp
                flags |= 0x01
        if len(body) > self._cfg.max_frame_size:
            raise FrameError("frame too large")

        header = uvarint_encode(len(body)) + bytes([flags])
        trailer = b""
        if self._cfg.enable_crc32:
            crc = zlib.crc32(payload) & 0xFFFFFFFF  # CRC over decompressed data
            trailer = struct.pack("!I", crc)

        packet = header + body + trailer

        if self._limiter:
            await self._limiter.acquire(amount=len(packet), timeout=5.0)

        t0 = time.monotonic()
        await self._b.write(packet)
        await self._b.drain()
        _telemetry(self._cfg.telemetry, "frame.write", None, {"bytes": float(len(packet)), "payload": float(len(payload)), "lat_ms": (time.monotonic() - t0) * 1000})

    async def aclose(self) -> None:
        await self._b.aclose()

class FramedAsyncReader:
    def __init__(self, base: AsyncReadable, cfg: FrameConfig = FrameConfig(), limiter: Optional[TokenBucket] = None) -> None:
        self._b = base
        self._cfg = cfg
        self._limiter = limiter

    async def read_frame(self) -> Optional[bytes]:
        """
        Returns payload (decompressed if needed) or None on EOF.
        """
        try:
            length = await auvarint_decode_from(self._b.readexactly)
        except StreamClosed:
            return None
        flags_b = await self._b.readexactly(1)
        flags = flags_b[0]
        if length > self._cfg.max_frame_size:
            raise FrameError("incoming frame too large")
        body = await self._b.readexactly(length)
        trailer = b""
        if self._cfg.enable_crc32:
            trailer = await self._b.readexactly(4)
        if self._limiter:
            await self._limiter.acquire(amount=length + 1 + (len(trailer) if trailer else 0), timeout=5.0)

        payload = zlib.decompress(body) if (flags & 0x01) else body
        if self._cfg.enable_crc32:
            want = struct.unpack("!I", trailer)[0]
            got = zlib.crc32(payload) & 0xFFFFFFFF
            if want != got:
                raise FrameError("crc mismatch")
        _telemetry(self._cfg.telemetry, "frame.read", None, {"bytes": float(length), "payload": float(len(payload))})
        return payload

    async def __aiter__(self) -> AsyncIterator[bytes]:
        while True:
            frame = await self.read_frame()
            if frame is None:
                break
            yield frame

    async def aclose(self) -> None:
        await self._b.aclose()

# =========================
# Multiplexing (channels over framed stream)
# =========================
# Envelope: [chan uvarint][type u8][payload...]
# type: 0=data, 1=close

class MuxAsyncWriter:
    def __init__(self, framed: FramedAsyncWriter) -> None:
        self._framed = framed

    async def send(self, channel: int, data: bytes) -> None:
        env = uvarint_encode(int(channel)) + bytes([0]) + bytes(data)
        await self._framed.write_frame(env)

    async def close_channel(self, channel: int) -> None:
        env = uvarint_encode(int(channel)) + bytes([1])
        await self._framed.write_frame(env)

    async def aclose(self) -> None:
        await self._framed.aclose()

class MuxAsyncReader:
    def __init__(self, framed: FramedAsyncReader) -> None:
        self._framed = framed
        self._closed_channels: Dict[int, bool] = {}

    async def recv(self) -> Optional[Tuple[int, bytes]]:
        frame = await self._framed.read_frame()
        if frame is None:
            return None
        # parse envelope
        def _rx(n: int) -> bytes:
            nonlocal frame, pos
            b = frame[pos:pos+n]
            if len(b) != n:
                raise FrameError("envelope short read")
            pos += n
            return b

        pos = 0
        # manual uvarint decode from memory buffer
        result = 0; shift = 0
        while True:
            if pos >= len(frame):
                raise FrameError("bad envelope varint")
            b = frame[pos]; pos += 1
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7

        chan = result
        if pos >= len(frame):
            raise FrameError("bad envelope (no type)")
        typ = frame[pos]; pos += 1
        if typ == 1:
            self._closed_channels[chan] = True
            return (chan, b"")
        data = frame[pos:]
        return (chan, data)

    async def __aiter__(self) -> AsyncIterator[Tuple[int, bytes]]:
        while True:
            item = await self.recv()
            if item is None:
                break
            yield item

    async def aclose(self) -> None:
        await self._framed.aclose()

# =========================
# Convenience: stream couple (create both ends)
# =========================

@dataclass
class PipeEnds:
    a_reader: FramedAsyncReader
    a_writer: FramedAsyncWriter
    b_reader: FramedAsyncReader
    b_writer: FramedAsyncWriter

def make_memory_framed_pipe(
    *,
    capacity: int = 256 * 1024,
    frame_cfg: FrameConfig = FrameConfig(),
) -> PipeEnds:
    """
    Returns two framed endpoints (A <-> B) over in-memory pipes.
    """
    a2b = InMemoryDuplex(capacity=capacity)
    b2a = InMemoryDuplex(capacity=capacity)

    a_reader = FramedAsyncReader(BufferedAsyncReader(b2a), frame_cfg)
    a_writer = FramedAsyncWriter(BufferedAsyncWriter(a2b), frame_cfg)

    b_reader = FramedAsyncReader(BufferedAsyncReader(a2b), frame_cfg)
    b_writer = FramedAsyncWriter(BufferedAsyncWriter(b2a), frame_cfg)
    return PipeEnds(a_reader, a_writer, b_reader, b_writer)

# =========================
# Sync framing (optional minimal)
# =========================

class FramedSyncWriter:
    def __init__(self, base: SyncWritable, enable_crc32: bool = True, enable_compress: bool = False, max_frame_size: int = 8*1024*1024) -> None:
        self._b = base
        self._crc = enable_crc32
        self._cmp = enable_compress
        self._max = max_frame_size

    def write_frame(self, payload: bytes) -> None:
        body = bytes(payload)
        flags = 0
        if self._cmp:
            comp = zlib.compress(body, level=6)
            if len(comp) < len(body):
                body = comp
                flags |= 0x01
        if len(body) > self._max:
            raise FrameError("frame too large")
        hdr = uvarint_encode(len(body)) + bytes([flags])
        tr = b""
        if self._crc:
            tr = struct.pack("!I", zlib.crc32(payload) & 0xFFFFFFFF)
        self._b.write(hdr + body + tr)

class FramedSyncReader:
    def __init__(self, base: SyncReadable, enable_crc32: bool = True, max_frame_size: int = 8*1024*1024) -> None:
        self._b = base
        self._crc = enable_crc32
        self._max = max_frame_size

    def read_frame(self) -> Optional[bytes]:
        try:
            length = uvarint_decode_from(self._b.readexactly)
        except StreamClosed:
            return None
        flags = self._b.readexactly(1)[0]
        if length > self._max:
            raise FrameError("incoming frame too large")
        body = self._b.readexactly(length)
        tr = self._b.readexactly(4) if self._crc else b""
        payload = zlib.decompress(body) if (flags & 0x01) else body
        if self._crc:
            want = struct.unpack("!I", tr)[0]
            got = zlib.crc32(payload) & 0xFFFFFFFF
            if want != got:
                raise FrameError("crc mismatch")
        return payload

# =========================
# Example utility: framed request/response (async)
# =========================

class RpcCodec:
    """
    Minimal request/response codec over FramedAsync*.
    Message: M = uvarint(msg_id) + uvarint(kind) + payload
      kind: 0=request, 1=response, 2=error
    """
    REQ, RES, ERR = 0, 1, 2

    @staticmethod
    def pack(msg_id: int, kind: int, payload: bytes) -> bytes:
        return uvarint_encode(msg_id) + uvarint_encode(kind) + bytes(payload)

    @staticmethod
    def unpack(b: bytes) -> Tuple[int, int, bytes]:
        pos = 0
        def rd() -> int:
            nonlocal pos
            res = 0; sh = 0
            for _ in range(10):
                if pos >= len(b):
                    raise FrameError("short rpc frame")
                x = b[pos]; pos += 1
                res |= (x & 0x7F) << sh
                if (x & 0x80) == 0:
                    return res
                sh += 7
            raise FrameError("rpc varint too long")
        mid = rd()
        kind = rd()
        return mid, kind, b[pos:]

# =========================
# __all__
# =========================

__all__ = [
    # errors
    "StreamError", "StreamClosed", "StreamTimeout", "StreamBackpressure", "FrameError",
    # sync
    "SyncReadable", "SyncWritable", "FileReadable", "FileWritable",
    "FramedSyncReader", "FramedSyncWriter",
    # async core
    "AsyncReadable", "AsyncWritable", "InMemoryDuplex",
    "BufferedAsyncReader", "BufferedAsyncWriter",
    # framing
    "FrameConfig", "FramedAsyncReader", "FramedAsyncWriter",
    # mux
    "MuxAsyncReader", "MuxAsyncWriter",
    # rate limiter
    "TokenBucket",
    # pipe
    "PipeEnds", "make_memory_framed_pipe",
    # rpc
    "RpcCodec",
    # varint
    "uvarint_encode", "uvarint_decode_from", "auvarint_decode_from",
    # telemetry
    "TelemetryHook",
]
