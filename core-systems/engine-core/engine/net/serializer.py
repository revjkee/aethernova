from __future__ import annotations

import struct
import zlib
from typing import Any, Iterable, Callable, Tuple, Optional

__all__ = [
    # Exceptions
    "SerializationError", "BoundsError", "NonMinimalVarintError", "TruncatedDataError",
    # Varint / ZigZag
    "varint32_encode", "varint32_decode", "varint64_encode", "varint64_decode",
    "zigzag32_encode", "zigzag32_decode", "zigzag64_encode", "zigzag64_decode",
    # Bit I/O
    "BitWriter", "BitReader",
    # Fixed / floats / strings / arrays
    "write_u8", "write_u16", "write_u32", "write_u64",
    "write_i32", "write_i64", "write_f32", "write_f64",
    "read_u8", "read_u16", "read_u32", "read_u64",
    "read_i32", "read_i64", "read_f32", "read_f64",
    "write_bytes", "read_bytes", "write_string", "read_string",
    "write_packed_varint32", "read_packed_varint32",
    "write_packed_varint64", "read_packed_varint64",
    # Envelope (versioned, optional compression+crc)
    "EnvelopeFlags", "serialize_envelope", "parse_envelope",
]

# ============================================================
# Exceptions
# ============================================================

class SerializationError(Exception):
    pass

class BoundsError(SerializationError):
    """Read/write beyond buffer bounds."""
    pass

class TruncatedDataError(SerializationError):
    """Unexpected end of buffer while decoding."""
    pass

class NonMinimalVarintError(SerializationError):
    """Varint uses non-minimal representation and STRICT mode is on."""
    pass


# ============================================================
# Varint / ZigZag encoding
# ============================================================

def varint32_encode(value: int) -> bytes:
    """LEB128-like, minimal length, 0..0xFFFFFFFF (masked to 32-bit)."""
    v = value & 0xFFFFFFFF
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)

def varint64_encode(value: int) -> bytes:
    v = value & 0xFFFFFFFFFFFFFFFF
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)

def varint32_decode(data: memoryview, pos: int = 0, *, strict_minimal: bool = True) -> Tuple[int, int]:
    """Return (value, new_pos). Raises for truncation or non-minimal if strict."""
    shift = 0
    result = 0
    start = pos
    while True:
        if pos >= len(data):
            raise TruncatedDataError("varint32 truncated")
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if b < 0x80:
            if result & ~0xFFFFFFFF:
                raise SerializationError("varint32 overflow")
            if strict_minimal:
                # Non-minimal encodings like 0x80 0x00 (should be 0x00) or leading zero 0x00 followed by anything
                if (pos - start) > 1 and (b == 0) and (result < (1 << shift)):
                    raise NonMinimalVarintError("non-minimal varint32")
                # Check that we didn't continue when high bits zero
                # Conservative additional check: recompute and compare length
                if varint32_encode(result) != bytes(data[start:pos]):
                    raise NonMinimalVarintError("non-minimal varint32")
            return result, pos
        shift += 7
        if shift > 35:
            raise SerializationError("varint32 too long")

def varint64_decode(data: memoryview, pos: int = 0, *, strict_minimal: bool = True) -> Tuple[int, int]:
    shift = 0
    result = 0
    start = pos
    while True:
        if pos >= len(data):
            raise TruncatedDataError("varint64 truncated")
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if b < 0x80:
            if result & ~0xFFFFFFFFFFFFFFFF:
                raise SerializationError("varint64 overflow")
            if strict_minimal:
                if varint64_encode(result) != bytes(data[start:pos]):
                    raise NonMinimalVarintError("non-minimal varint64")
            return result, pos
        shift += 7
        if shift > 70:
            raise SerializationError("varint64 too long")

def zigzag32_encode(value: int) -> int:
    # Map signed to unsigned: 0->0, -1->1, 1->2, -2->3, ...
    return ((value << 1) ^ (value >> 31)) & 0xFFFFFFFF

def zigzag32_decode(value: int) -> int:
    return (value >> 1) ^ (-(value & 1))

def zigzag64_encode(value: int) -> int:
    return ((value << 1) ^ (value >> 63)) & 0xFFFFFFFFFFFFFFFF

def zigzag64_decode(value: int) -> int:
    return (value >> 1) ^ (-(value & 1))


# ============================================================
# Bit-level Writer/Reader
# ============================================================

class BitWriter:
    """
    Buffered bit writer.
    - write_bits(n, v): up to 64 bits.
    - align(): to next byte boundary.
    - write_bytes(b): must be aligned.
    """
    __slots__ = ("_buf", "_byte", "_bitpos", "_max_size")

    def __init__(self, initial_capacity: int = 64, max_size: Optional[int] = None) -> None:
        self._buf = bytearray(initial_capacity)
        self._byte = 0
        self._bitpos = 0  # bits filled in _byte [0..7]
        self._max_size = max_size

    def _ensure_capacity(self, extra: int) -> None:
        if self._max_size is not None and len(self._buf) + max(0, extra) > self._max_size:
            raise BoundsError("BitWriter max_size exceeded")

    def write_bits(self, nbits: int, value: int) -> None:
        if not (0 <= nbits <= 64):
            raise SerializationError("nbits must be in [0,64]")
        v = value & ((1 << nbits) - 1) if nbits < 64 else value & 0xFFFFFFFFFFFFFFFF
        while nbits > 0:
            take = min(8 - self._bitpos, nbits)
            mask = ((1 << take) - 1)
            chunk = v & mask
            v >>= take
            self._byte |= (chunk & 0xFF) << self._bitpos
            self._bitpos += take
            nbits -= take
            if self._bitpos == 8:
                self._flush_byte()

    def _flush_byte(self) -> None:
        self._ensure_capacity(1)
        self._buf.append(self._byte & 0xFF)
        self._byte = 0
        self._bitpos = 0

    def align(self) -> None:
        if self._bitpos:
            self._flush_byte()

    def write_bytes(self, b: bytes | bytearray | memoryview) -> None:
        if self._bitpos != 0:
            raise SerializationError("BitWriter not aligned")
        mv = memoryview(b)
        self._ensure_capacity(len(mv))
        self._buf.extend(mv.tobytes())

    def getvalue(self) -> bytes:
        if self._bitpos:
            self._flush_byte()
        return bytes(self._buf)


class BitReader:
    """
    Buffered bit reader over bytes-like.
    - read_bits(n): up to 64 bits.
    - align(): to next byte boundary.
    - read_bytes(n): must be aligned.
    """
    __slots__ = ("_mv", "_pos", "_byte", "_bitpos", "_eof")

    def __init__(self, data: bytes | bytearray | memoryview) -> None:
        self._mv = memoryview(data)
        self._pos = 0
        self._byte = 0
        self._bitpos = 8  # force load on first read
        self._eof = len(self._mv)

    def _need_byte(self) -> None:
        if self._pos >= self._eof:
            raise TruncatedDataError("read past end")
        self._byte = self._mv[self._pos]
        self._pos += 1
        self._bitpos = 0

    def read_bits(self, nbits: int) -> int:
        if not (0 <= nbits <= 64):
            raise SerializationError("nbits must be in [0,64]")
        v = 0
        shift = 0
        while nbits > 0:
            if self._bitpos == 8:
                self._need_byte()
            take = min(8 - self._bitpos, nbits)
            chunk = (self._byte >> self._bitpos) & ((1 << take) - 1)
            v |= chunk << shift
            self._bitpos += take
            nbits -= take
            shift += take
        return v

    def align(self) -> None:
        if self._bitpos != 8 and self._bitpos != 0:
            # consume remainder of current byte
            self._bitpos = 8

    def read_bytes(self, n: int) -> bytes:
        if self._bitpos != 8 and self._bitpos != 0:
            raise SerializationError("BitReader not aligned")
        end = self._pos + n
        if end > self._eof:
            raise TruncatedDataError("read past end")
        out = self._mv[self._pos:end].tobytes()
        self._pos = end
        return out

    @property
    def remaining(self) -> int:
        # remaining bytes (ignores partial byte)
        if self._bitpos == 8 or self._bitpos == 0:
            return self._eof - self._pos
        # there are pending bits in current byte
        return self._eof - self._pos + 1


# ============================================================
# Fixed-width integers / floats / bytes / strings
# ============================================================

_ENDIAN_PREFIX = {
    "little": "<",
    "big": ">",
    "<": "<",
    ">": ">",
}

def _prefix(endian: str) -> str:
    try:
        return _ENDIAN_PREFIX[endian]
    except KeyError:
        raise SerializationError("endian must be 'little' or 'big' (or '<'/'>' prefix)")

def write_u8(buf: bytearray, v: int) -> None:
    if not (0 <= v <= 0xFF):
        raise SerializationError("u8 out of range")
    buf.append(v & 0xFF)

def write_u16(buf: bytearray, v: int, endian: str = "little") -> None:
    buf.extend(struct.pack(_prefix(endian) + "H", v & 0xFFFF))

def write_u32(buf: bytearray, v: int, endian: str = "little") -> None:
    buf.extend(struct.pack(_prefix(endian) + "I", v & 0xFFFFFFFF))

def write_u64(buf: bytearray, v: int, endian: str = "little") -> None:
    buf.extend(struct.pack(_prefix(endian) + "Q", v & 0xFFFFFFFFFFFFFFFF))

def write_i32(buf: bytearray, v: int, endian: str = "little") -> None:
    buf.extend(struct.pack(_prefix(endian) + "i", int(v)))

def write_i64(buf: bytearray, v: int, endian: str = "little") -> None:
    buf.extend(struct.pack(_prefix(endian) + "q", int(v)))

def write_f32(buf: bytearray, v: float, endian: str = "little") -> None:
    buf.extend(struct.pack(_prefix(endian) + "f", float(v)))

def write_f64(buf: bytearray, v: float, endian: str = "little") -> None:
    buf.extend(struct.pack(_prefix(endian) + "d", float(v)))

def read_u8(mv: memoryview, pos: int = 0) -> Tuple[int, int]:
    if pos >= len(mv): raise TruncatedDataError("u8")
    return mv[pos], pos + 1

def read_u16(mv: memoryview, pos: int = 0, endian: str = "little") -> Tuple[int, int]:
    size = 2
    end = pos + size
    if end > len(mv): raise TruncatedDataError("u16")
    return struct.unpack_from(_prefix(endian) + "H", mv, pos)[0], end

def read_u32(mv: memoryview, pos: int = 0, endian: str = "little") -> Tuple[int, int]:
    size = 4
    end = pos + size
    if end > len(mv): raise TruncatedDataError("u32")
    return struct.unpack_from(_prefix(endian) + "I", mv, pos)[0], end

def read_u64(mv: memoryview, pos: int = 0, endian: str = "little") -> Tuple[int, int]:
    size = 8
    end = pos + size
    if end > len(mv): raise TruncatedDataError("u64")
    return struct.unpack_from(_prefix(endian) + "Q", mv, pos)[0], end

def read_i32(mv: memoryview, pos: int = 0, endian: str = "little") -> Tuple[int, int]:
    size = 4
    end = pos + size
    if end > len(mv): raise TruncatedDataError("i32")
    return struct.unpack_from(_prefix(endian) + "i", mv, pos)[0], end

def read_i64(mv: memoryview, pos: int = 0, endian: str = "little") -> Tuple[int, int]:
    size = 8
    end = pos + size
    if end > len(mv): raise TruncatedDataError("i64")
    return struct.unpack_from(_prefix(endian) + "q", mv, pos)[0], end

def read_f32(mv: memoryview, pos: int = 0, endian: str = "little") -> Tuple[float, int]:
    size = 4
    end = pos + size
    if end > len(mv): raise TruncatedDataError("f32")
    return struct.unpack_from(_prefix(endian) + "f", mv, pos)[0], end

def read_f64(mv: memoryview, pos: int = 0, endian: str = "little") -> Tuple[float, int]:
    size = 8
    end = pos + size
    if end > len(mv): raise TruncatedDataError("f64")
    return struct.unpack_from(_prefix(endian) + "d", mv, pos)[0], end

def write_bytes(buf: bytearray, b: bytes | bytearray | memoryview) -> None:
    buf.extend(memoryview(b))

def read_bytes(mv: memoryview, pos: int, n: int) -> Tuple[bytes, int]:
    end = pos + n
    if end > len(mv):
        raise TruncatedDataError("bytes")
    return mv[pos:end].tobytes(), end

def write_string(buf: bytearray, s: str, *, encoding: str = "utf-8") -> None:
    b = s.encode(encoding)
    buf.extend(varint32_encode(len(b)))
    buf.extend(b)

def read_string(mv: memoryview, pos: int, *, encoding: str = "utf-8", strict_minimal: bool = True) -> Tuple[str, int]:
    n, pos = varint32_decode(mv, pos, strict_minimal=strict_minimal)
    data, pos = read_bytes(mv, pos, n)
    return data.decode(encoding), pos


# ============================================================
# Packed arrays (length-prefixed)
# ============================================================

def write_packed_varint32(buf: bytearray, values: Iterable[int]) -> None:
    # count + payload (minimal varints)
    values = list(values)
    buf.extend(varint32_encode(len(values)))
    for v in values:
        buf.extend(varint32_encode(v))

def read_packed_varint32(mv: memoryview, pos: int, *, strict_minimal: bool = True) -> Tuple[list[int], int]:
    count, pos = varint32_decode(mv, pos, strict_minimal=strict_minimal)
    out: list[int] = []
    for _ in range(count):
        v, pos = varint32_decode(mv, pos, strict_minimal=strict_minimal)
        out.append(v)
    return out, pos

def write_packed_varint64(buf: bytearray, values: Iterable[int]) -> None:
    values = list(values)
    buf.extend(varint32_encode(len(values)))
    for v in values:
        buf.extend(varint64_encode(v))

def read_packed_varint64(mv: memoryview, pos: int, *, strict_minimal: bool = True) -> Tuple[list[int], int]:
    count, pos = varint32_decode(mv, pos, strict_minimal=strict_minimal)
    out: list[int] = []
    for _ in range(count):
        v, pos = varint64_decode(mv, pos, strict_minimal=strict_minimal)
        out.append(v)
    return out, pos


# ============================================================
# Versioned Envelope with compression + CRC32
# ============================================================

class EnvelopeFlags:
    COMPRESSED = 0x01   # zlib DEFLATE
    CRC32 = 0x02        # CRC32 appended to the end of envelope

_MAGIC = b"EN"
_VERSION = 1

def serialize_envelope(payload: bytes, *, compressed: bool = False, with_crc32: bool = True) -> bytes:
    """
    Envelope v1:
      magic[2]="EN" | version[u8]=1 | flags[u8] | length[varint32] | data[length] | [crc32 u32]
    If COMPRESSED flag set: data = zlib.compress(payload), else data = payload.
    CRC32 covers: magic..data bytes (everything before CRC).
    """
    data = zlib.compress(payload) if compressed else payload
    flags = 0
    if compressed:
        flags |= EnvelopeFlags.COMPRESSED
    if with_crc32:
        flags |= EnvelopeFlags.CRC32

    buf = bytearray()
    buf.extend(_MAGIC)
    write_u8(buf, _VERSION)
    write_u8(buf, flags)
    buf.extend(varint32_encode(len(data)))
    write_bytes(buf, data)

    if with_crc32:
        crc = zlib.crc32(memoryview(buf)) & 0xFFFFFFFF
        write_u32(buf, crc, endian="big")  # network order for CRC

    return bytes(buf)

def parse_envelope(blob: bytes, *, strict_minimal: bool = True, max_size: Optional[int] = None) -> bytes:
    """
    Parse v1 envelope, return raw payload (decompressed if needed).
    Validates magic/version, length bounds, and optional CRC32.
    """
    mv = memoryview(blob)
    pos = 0
    if len(mv) < 4:
        raise TruncatedDataError("envelope header")
    if bytes(mv[0:2]) != _MAGIC:
        raise SerializationError("bad magic")
    pos = 2
    ver = mv[pos]; pos += 1
    if ver != _VERSION:
        raise SerializationError(f"unsupported version {ver}")
    flags = mv[pos]; pos += 1

    length, pos = varint32_decode(mv, pos, strict_minimal=strict_minimal)
    if max_size is not None and length > max_size:
        raise BoundsError("payload too large")
    end_of_data = pos + length
    if end_of_data > len(mv):
        raise TruncatedDataError("envelope data")

    data = mv[pos:end_of_data].tobytes()
    pos = end_of_data

    if flags & EnvelopeFlags.CRC32:
        # CRC is big-endian u32 at the end
        if pos + 4 > len(mv):
            raise TruncatedDataError("crc32")
        crc_expected = struct.unpack_from(">I", mv, pos)[0]
        crc_actual = zlib.crc32(mv[:pos]) & 0xFFFFFFFF
        if crc_expected != crc_actual:
            raise SerializationError("crc32 mismatch")
        pos += 4

    if pos != len(mv):
        # Trailing bytes not allowed
        raise SerializationError("unexpected trailing bytes")

    if flags & EnvelopeFlags.COMPRESSED:
        try:
            return zlib.decompress(data)
        except zlib.error as e:
            raise SerializationError(f"zlib: {e}") from e
    return data
