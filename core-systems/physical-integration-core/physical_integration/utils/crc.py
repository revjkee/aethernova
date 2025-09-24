# physical-integration-core/physical_integration/utils/crc.py
"""
Universal CRC utilities for Physical Integration Core.

Features:
- Parameterized CRC engine (width 8..64, poly, init, refin/refout, xorout)
- Precomputed 256-entry table per spec (MSB-first and LSB-first supported)
- Streaming API: update(), digest(), hexdigest(), copy()
- Presets for common industrial CRCs (CRC-8, CRC-16 family, CRC-32, CRC-32C, CRC-64/ECMA)
- Safe bit-width masking; efficient processing via memoryview
- Pure Python, no external deps; type hints for clarity

Note:
- Polynomials are specified in the "normal" (MSB-first) form, e.g. CRC-32 poly 0x04C11DB7,
  CRC-32C poly 0x1EDC6F41, CRC-16/IBM poly 0x8005, CRC-64/ECMA 0x42F0E1EBA9EA3693.
- For refin=True the internal table uses the reflected polynomial implicitly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Iterable, Tuple

# ---------------------------
# Helpers
# ---------------------------

def _mask(width: int) -> int:
    return (1 << width) - 1 if width < 64 else (1 << 64) - 1

def _topbit(width: int) -> int:
    return 1 << (width - 1)

def _reflect_bits(x: int, width: int) -> int:
    y = 0
    for i in range(width):
        if (x >> i) & 1:
            y |= 1 << (width - 1 - i)
    return y

# ---------------------------
# CRC Spec and Engine
# ---------------------------

@dataclass(frozen=True)
class CRCSpec:
    name: str
    width: int
    poly: int          # polynomial in normal form (MSB-first)
    init: int
    refin: bool
    refout: bool
    xorout: int

    def masked(self) -> "CRCSpec":
        m = _mask(self.width)
        return CRCSpec(
            name=self.name,
            width=self.width,
            poly=self.poly & m,
            init=self.init & m,
            refin=self.refin,
            refout=self.refout,
            xorout=self.xorout & m,
        )

class CRC:
    """
    Streaming CRC instance.
    Usage:
        c = CRC.compile(PRESETS["CRC-32"])
        c.update(b"data")
        value = c.digest()          # int
        hexstr = c.hexdigest()      # zero-padded hex
    """

    __slots__ = ("spec", "_tbl", "_crc", "_mask", "_shift")

    def __init__(self, spec: CRCSpec, table: Tuple[int, ...]) -> None:
        s = spec.masked()
        self.spec = s
        self._tbl = table
        self._crc = s.init
        self._mask = _mask(s.width)
        self._shift = s.width - 8  # for MSB-first path

    @staticmethod
    def compile(spec: CRCSpec) -> "CRC":
        """
        Build CRC with a precomputed 256-entry table for the given spec.
        """
        s = spec.masked()
        tbl = _build_table(s)
        return CRC(s, tbl)

    def copy(self) -> "CRC":
        new = CRC.__new__(CRC)  # type: ignore
        new.spec = self.spec
        new._tbl = self._tbl
        new._crc = self._crc
        new._mask = self._mask
        new._shift = self._shift
        return new

    # --------------- streaming ----------------
    def reset(self) -> None:
        self._crc = self.spec.init

    def update(self, data: bytes | bytearray | memoryview) -> None:
        if not data:
            return
        mv = data if isinstance(data, memoryview) else memoryview(data)
        if self.spec.refin:
            crc = self._crc
            tbl = self._tbl
            for b in mv.tobytes():  # fast path through Python's C loop
                crc = tbl[(crc ^ b) & 0xFF] ^ (crc >> 8)
            self._crc = crc & self._mask
        else:
            crc = self._crc
            tbl = self._tbl
            shift = self._shift
            mask = self._mask
            for b in mv.tobytes():
                idx = ((crc >> shift) ^ b) & 0xFF
                crc = tbl[idx] ^ ((crc << 8) & mask)
            self._crc = crc & mask

    def digest(self) -> int:
        crc = self._crc
        if self.spec.refout != self.spec.refin:
            crc = _reflect_bits(crc, self.spec.width)
        return (crc ^ self.spec.xorout) & self._mask

    def hexdigest(self) -> str:
        width = self.spec.width
        nibbles = (width + 3) // 4
        return f"{self.digest():0{nibbles}x}"

# ---------------------------
# Table builder
# ---------------------------

def _build_table(spec: CRCSpec) -> Tuple[int, ...]:
    """
    Build a 256-entry table for the given spec.
    For refin=True, uses LSB-first (reflected) progression.
    For refin=False, uses MSB-first progression.
    """
    width = spec.width
    poly = spec.poly & _mask(width)
    if spec.refin:
        # Use reflected polynomial for LSB-first math
        rpoly = _reflect_bits(poly, width)
        tbl = []
        for i in range(256):
            crc = i
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ rpoly
                else:
                    crc >>= 1
            tbl.append(crc & _mask(width))
        return tuple(tbl)
    else:
        top = _topbit(width)
        tbl = []
        for i in range(256):
            crc = i << (width - 8)
            for _ in range(8):
                if crc & top:
                    crc = ((crc << 1) & _mask(width)) ^ poly
                else:
                    crc = (crc << 1) & _mask(width)
            tbl.append(crc & _mask(width))
        return tuple(tbl)

# ---------------------------
# One-shot helpers and presets
# ---------------------------

def compute(spec_or_name: CRCSpec | str, data: bytes | bytearray | memoryview) -> int:
    """
    Compute CRC value for the given data in one call.
    """
    spec = spec_or_name if isinstance(spec_or_name, CRCSpec) else PRESETS[spec_or_name]
    c = CRC.compile(spec)
    c.update(data)
    return c.digest()

def hexdigest(spec_or_name: CRCSpec | str, data: bytes | bytearray | memoryview) -> str:
    spec = spec_or_name if isinstance(spec_or_name, CRCSpec) else PRESETS[spec_or_name]
    c = CRC.compile(spec)
    c.update(data)
    return c.hexdigest()

# Common industry presets (polynomials in normal form)
PRESETS: Dict[str, CRCSpec] = {
    # 8-bit
    "CRC-8": CRCSpec(name="CRC-8", width=8, poly=0x07, init=0x00, refin=False, refout=False, xorout=0x00),
    "CRC-8/MAXIM": CRCSpec(name="CRC-8/MAXIM", width=8, poly=0x31, init=0x00, refin=True, refout=True, xorout=0x00),

    # 16-bit
    "CRC-16/IBM": CRCSpec(name="CRC-16/IBM", width=16, poly=0x8005, init=0x0000, refin=True, refout=True, xorout=0x0000),   # aka ARC
    "CRC-16/MODBUS": CRCSpec(name="CRC-16/MODBUS", width=16, poly=0x8005, init=0xFFFF, refin=True, refout=True, xorout=0x0000),
    "CRC-16/CCITT-FALSE": CRCSpec(name="CRC-16/CCITT-FALSE", width=16, poly=0x1021, init=0xFFFF, refin=False, refout=False, xorout=0x0000),
    "CRC-16/KERMIT": CRCSpec(name="CRC-16/KERMIT", width=16, poly=0x1021, init=0x0000, refin=True, refout=True, xorout=0x0000),
    "CRC-16/X25": CRCSpec(name="CRC-16/X25", width=16, poly=0x1021, init=0xFFFF, refin=True, refout=True, xorout=0xFFFF),

    # 32-bit
    "CRC-32": CRCSpec(name="CRC-32", width=32, poly=0x04C11DB7, init=0xFFFFFFFF, refin=True, refout=True, xorout=0xFFFFFFFF),  # ISO-HDLC/IEEE 802.3
    "CRC-32C": CRCSpec(name="CRC-32C", width=32, poly=0x1EDC6F41, init=0xFFFFFFFF, refin=True, refout=True, xorout=0xFFFFFFFF), # Castagnoli

    # 64-bit
    "CRC-64/ECMA-182": CRCSpec(name="CRC-64/ECMA-182", width=64, poly=0x42F0E1EBA9EA3693, init=0x0000000000000000, refin=False, refout=False, xorout=0x0000000000000000),
}

# ---------------------------
# Self-check (optional manual run)
# ---------------------------

if __name__ == "__main__":
    msg = b"123456789"
    for name in (
        "CRC-8", "CRC-8/MAXIM",
        "CRC-16/IBM", "CRC-16/MODBUS", "CRC-16/CCITT-FALSE", "CRC-16/KERMIT", "CRC-16/X25",
        "CRC-32", "CRC-32C",
        "CRC-64/ECMA-182",
    ):
        val = hexdigest(name, msg)
        print(f"{name:18s}  123456789 -> 0x{val}")
