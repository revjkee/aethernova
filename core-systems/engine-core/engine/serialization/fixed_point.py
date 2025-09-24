# -*- coding: utf-8 -*-
"""
Fixed-point serialization (industrial-grade)

Задачи:
- Детерминированное представление чисел с фиксированной точкой (fixed-point) для сериализации.
- Единый контракт: Decimal/float <-> Fixed (целое значение + формат).
- Безопасность: защита от переполнений, контроль шкалы, предсказуемое округление.
- Форматы: Qm.n (total_bits, frac_bits, signed), endianness little/big.
- Режимы округления: nearest_even (bankers), nearest_away, down, up, toward_zero.
- Политика насыщения: saturate=True (обрезать к допустимому диапазону) или бросать OverflowError.
- Варинты: ULEB128, ZigZag для целых метаданных/относительных значений.
- Массивы: пакетная упаковка/распаковка без перегрева ГЦ.
- Версии и контроль целостности (опциональный CRC32).
- Никакой привязки к платформенным float/IEEE‑754: все критические шаги через Decimal.

Использование:
    fmt = FixedPointFormat(total_bits=16, frac_bits=8, signed=True)  # Q7.8
    x = Fixed.from_decimal(Decimal("12.75"), fmt)
    data = x.to_bytes()  # сериализация
    y = Fixed.from_bytes(data)       # десериализация
    f = y.to_decimal()               # Decimal("12.75")

Примечание: float поддержаны, но для точности используйте Decimal.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from decimal import Decimal, getcontext, ROUND_HALF_EVEN, ROUND_HALF_UP, ROUND_FLOOR, ROUND_CEILING
from typing import Iterable, List, Literal, Tuple, Optional

# Контекст Decimal: высокая точность для промежуточных рассчетов
getcontext().prec = 128

# ------------------------------ Исключения ------------------------------ #

class FixedPointError(Exception):
    pass

class FixedPointFormatError(FixedPointError):
    pass

class FixedPointOverflow(FixedPointError):
    pass

class FixedPointScaleError(FixedPointError):
    pass

# ------------------------------ Кодеки varint/zigzag ------------------------------ #

def zigzag_encode(n: int) -> int:
    return (n << 1) ^ (n >> 63) if n < 0 else (n << 1)

def zigzag_decode(u: int) -> int:
    return (u >> 1) ^ -(u & 1)

def uleb128_encode(n: int) -> bytes:
    if n < 0:
        raise ValueError("ULEB128 expects non-negative")
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)

def uleb128_decode(data: bytes, offset: int = 0) -> Tuple[int, int]:
    shift = 0
    result = 0
    i = offset
    while True:
        if i >= len(data):
            raise ValueError("ULEB128 truncated")
        b = data[i]
        i += 1
        result |= ((b & 0x7F) << shift)
        if (b & 0x80) == 0:
            break
        shift += 7
        if shift > 63:
            raise ValueError("ULEB128 too large")
    return result, i

# ------------------------------ Формат Qm.n ------------------------------ #

RoundingMode = Literal["nearest_even", "nearest_away", "down", "up", "toward_zero"]
Endian = Literal["little", "big"]

@dataclass(frozen=True)
class FixedPointFormat:
    total_bits: int
    frac_bits: int
    signed: bool
    endian: Endian = "little"
    rounding: RoundingMode = "nearest_even"
    saturate: bool = True
    version: int = 1  # для сериализации заголовка

    def __post_init__(self):
        if self.total_bits <= 0 or self.frac_bits < 0:
            raise FixedPointFormatError("invalid bit widths")
        if self.frac_bits >= self.total_bits:
            raise FixedPointFormatError("frac_bits must be < total_bits")
        if self.endian not in ("little", "big"):
            raise FixedPointFormatError("invalid endian")
        if self.rounding not in ("nearest_even", "nearest_away", "down", "up", "toward_zero"):
            raise FixedPointFormatError("invalid rounding")

    @property
    def int_bits(self) -> int:
        return self.total_bits - self.frac_bits - (1 if self.signed else 0)

    @property
    def scale(self) -> Decimal:
        return Decimal(1) / (Decimal(1) << self.frac_bits)

    @property
    def min_int(self) -> int:
        if self.signed:
            return -(1 << (self.total_bits - 1))
        return 0

    @property
    def max_int(self) -> int:
        if self.signed:
            return (1 << (self.total_bits - 1)) - 1
        return (1 << self.total_bits) - 1

    def q_notation(self) -> str:
        # Q(int_bits).(frac_bits) для наглядности
        m = self.total_bits - self.frac_bits - (1 if self.signed else 0)
        s = "Q" + ("s" if self.signed else "u")
        return f"{s}{m}.{self.frac_bits}"

# ------------------------------ Внутренняя математика ------------------------------ #

def _round_decimal(d: Decimal, rounding: RoundingMode) -> Decimal:
    if rounding == "nearest_even":
        return d.to_integral_value(rounding=ROUND_HALF_EVEN)
    if rounding == "nearest_away":
        # округление до ближайшего, при .5 от нуля
        sign = -1 if d < 0 else 1
        return (abs(d) + Decimal("0.5")).to_integral_value(rounding=ROUND_FLOOR) * sign
    if rounding == "down":      # floor
        return d.to_integral_value(rounding=ROUND_FLOOR)
    if rounding == "up":        # ceil
        return d.to_integral_value(rounding=ROUND_CEILING)
    if rounding == "toward_zero":
        # отсечение дробной части
        return Decimal(int(d))
    raise FixedPointFormatError("unknown rounding")

def _saturate(n: int, fmt: FixedPointFormat) -> int:
    if n < fmt.min_int:
        return fmt.min_int
    if n > fmt.max_int:
        return fmt.max_int
    return n

def _check_range(n: int, fmt: FixedPointFormat) -> None:
    if n < fmt.min_int or n > fmt.max_int:
        raise FixedPointOverflow(f"value {n} out of range [{fmt.min_int}, {fmt.max_int}] for {fmt.q_notation()}")

def _twos_complement_to_signed(n: int, bits: int) -> int:
    sign_bit = 1 << (bits - 1)
    return (n ^ sign_bit) - sign_bit

def _signed_to_twos_complement(n: int, bits: int) -> int:
    mask = (1 << bits) - 1
    return n & mask

# ------------------------------ Основной тип Fixed ------------------------------ #

MAGIC = b"FPX"  # заголовок
HEADER_VERSION = 1

class Fixed:
    """
    Контейнер фикс‑пойнт: хранит целое представление (raw) и формат.
    raw — это целое значение в формате Q: value_fixed = raw / (1 << frac_bits).
    """

    __slots__ = ("raw", "fmt")

    def __init__(self, raw: int, fmt: FixedPointFormat):
        self.raw = int(raw)
        self.fmt = fmt
        _check_range(self.raw, self.fmt)

    # ---------- Создание ---------- #

    @staticmethod
    def from_decimal(d: Decimal, fmt: FixedPointFormat) -> "Fixed":
        scaled = d / fmt.scale  # d * 2^frac_bits
        q = _round_decimal(scaled, fmt.rounding)
        n = int(q)
        if fmt.saturate:
            n = _saturate(n, fmt)
        else:
            _check_range(n, fmt)
        return Fixed(n, fmt)

    @staticmethod
    def from_float(f: float, fmt: FixedPointFormat) -> "Fixed":
        # Важно: конвертируем через Decimal(str(f)) — избегаем binary float артефактов
        return Fixed.from_decimal(Decimal(str(f)), fmt)

    @staticmethod
    def from_bytes(data: bytes) -> "Fixed":
        """
        Формат:
        [3b MAGIC 'FPX'][1b ver][1b total_bits][1b frac_bits][1b flags][1b endian][1b rounding][1b options]
        [varint raw_len][raw_bytes][crc32 (4b, опционально если установлен бит опции)]
        flags: bit0 = signed
        endian: 0=little,1=big
        rounding: 0 NE, 1 NA, 2 DOWN, 3 UP, 4 TZ
        options: bit0 = saturate, bit1 = crc32_present
        """
        if len(data) < 7:
            raise FixedPointFormatError("data too short")
        if data[0:3] != MAGIC:
            raise FixedPointFormatError("bad magic")
        ver = data[3]
        if ver != HEADER_VERSION:
            raise FixedPointFormatError(f"unsupported header version {ver}")
        total_bits = data[4]
        frac_bits = data[5]
        flags = data[6]
        endian_b = data[7]
        rounding_b = data[8]
        options = data[9]
        off = 10

        signed = bool(flags & 0x01)
        endian = "little" if endian_b == 0 else "big"
        rounding_map = {0: "nearest_even", 1: "nearest_away", 2: "down", 3: "up", 4: "toward_zero"}
        if rounding_b not in rounding_map:
            raise FixedPointFormatError("bad rounding code")
        rounding = rounding_map[rounding_b]
        saturate = bool(options & 0x01)
        has_crc = bool(options & 0x02)

        raw_len, off = uleb128_decode(data, off)
        if raw_len <= 0 or off + raw_len > len(data):
            raise FixedPointFormatError("invalid raw length")
        raw_bytes = data[off: off + raw_len]
        off += raw_len

        if has_crc:
            if off + 4 > len(data):
                raise FixedPointFormatError("missing crc32")
            crc = struct.unpack(">I", data[off: off+4])[0]
            calc = zlib.crc32(data[0: off]) & 0xFFFFFFFF
            if crc != calc:
                raise FixedPointFormatError("crc32 mismatch")

        # восстановим целое согласно знаковости и эндийнессу
        raw_int = int.from_bytes(raw_bytes, byteorder=endian, signed=False)
        if signed:
            raw_int = _twos_complement_to_signed(raw_int, total_bits)

        fmt = FixedPointFormat(
            total_bits=total_bits,
            frac_bits=frac_bits,
            signed=signed,
            endian=endian, rounding=rounding, saturate=saturate, version=ver
        )
        return Fixed(raw_int, fmt)

    # ---------- Преобразования ---------- #

    def to_decimal(self) -> Decimal:
        return Decimal(self.raw) * self.fmt.scale

    def to_float(self) -> float:
        # потеря детерминизма допустима только по запросу
        return float(self.to_decimal())

    # ---------- Сериализация ---------- #

    def to_bytes(self, with_crc32: bool = False) -> bytes:
        # кодируем raw по модулю, затем добавим заголовок и признак знака
        if self.fmt.signed:
            unsigned = _signed_to_twos_complement(self.raw, self.fmt.total_bits)
        else:
            unsigned = self.raw
        raw_len = (self.fmt.total_bits + 7) // 8
        raw_bytes = int(unsigned).to_bytes(raw_len, byteorder=self.fmt.endian, signed=False)

        flags = (0x01 if self.fmt.signed else 0x00)
        endian_b = 0 if self.fmt.endian == "little" else 1
        rounding_map = {"nearest_even": 0, "nearest_away": 1, "down": 2, "up": 3, "toward_zero": 4}
        rounding_b = rounding_map[self.fmt.rounding]
        options = (0x01 if self.fmt.saturate else 0x00) | (0x02 if with_crc32 else 0x00)

        out = bytearray()
        out += MAGIC
        out.append(self.fmt.version)
        out.append(self.fmt.total_bits)
        out.append(self.fmt.frac_bits)
        out.append(flags)
        out.append(endian_b)
        out.append(rounding_b)
        out.append(options)
        out += uleb128_encode(len(raw_bytes))
        out += raw_bytes
        if with_crc32:
            crc = zlib.crc32(bytes(out)) & 0xFFFFFFFF
            out += struct.pack(">I", crc)
        return bytes(out)

    # ---------- Операции ---------- #

    def _binary_op(self, other: "Fixed", op: str, out_fmt: Optional[FixedPointFormat] = None) -> "Fixed":
        if not isinstance(other, Fixed):
            raise TypeError("Fixed required")
        # Нормализация к общему масштабу: приведем к максимальной frac_bits
        f1, f2 = self.fmt, other.fmt
        frac = max(f1.frac_bits, f2.frac_bits)
        # расширим до общего масштаба
        a = self.raw << (frac - f1.frac_bits)
        b = other.raw << (frac - f2.frac_bits)

        if op == "add":
            raw = a + b
            tgt_signed = f1.signed or f2.signed
            total_bits = max(f1.total_bits, f2.total_bits) + 1  # +1 на перенос
            res_fmt = out_fmt or FixedPointFormat(total_bits=total_bits, frac_bits=frac, signed=tgt_signed,
                                                  endian=f1.endian, rounding=f1.rounding, saturate=True)
            return Fixed(_saturate(raw, res_fmt) if res_fmt.saturate else raw, res_fmt)

        if op == "sub":
            raw = a - b
            tgt_signed = True  # вычитание может дать отрицательный
            total_bits = max(f1.total_bits, f2.total_bits) + 1
            res_fmt = out_fmt or FixedPointFormat(total_bits=total_bits, frac_bits=frac, signed=tgt_signed,
                                                  endian=f1.endian, rounding=f1.rounding, saturate=True)
            return Fixed(_saturate(raw, res_fmt) if res_fmt.saturate else raw, res_fmt)

        if op == "mul":
            # (a/2^fa) * (b/2^fb) = (a*b)/2^(fa+fb)
            raw_wide = a * b
            frac_out = frac * 2
            # приведем к желаемому out_fmt или сократим до разумных бит
            if out_fmt:
                shift = frac_out - out_fmt.frac_bits
                if shift >= 0:
                    adj = Decimal(raw_wide) / (Decimal(1) << shift)
                    raw = int(_round_decimal(adj, out_fmt.rounding))
                else:
                    raw = raw_wide << (-shift)
                res_fmt = out_fmt
            else:
                # по умолчанию отбрасываем половину дробной части с округлением до исходного frac
                shift = frac
                adj = Decimal(raw_wide) / (Decimal(1) << shift)
                raw = int(_round_decimal(adj, f1.rounding))
                res_fmt = FixedPointFormat(total_bits=f1.total_bits + f2.int_bits + 2, frac_bits=frac,
                                           signed=(f1.signed or f2.signed), endian=f1.endian, rounding=f1.rounding, saturate=True)
            raw = _saturate(raw, res_fmt) if res_fmt.saturate else raw
            return Fixed(raw, res_fmt)

        if op == "div":
            # (a/2^fa) / (b/2^fb) = (a * 2^fb) / b
            if b == 0:
                raise ZeroDivisionError("division by zero")
            numerator = a << frac  # * 2^frac to keep frac
            q = Decimal(numerator) / Decimal(b)
            if out_fmt:
                # под заданный frac
                shift = out_fmt.frac_bits - frac
                if shift >= 0:
                    q = q * (Decimal(1) << shift)
                else:
                    q = q / (Decimal(1) << (-shift))
                raw = int(_round_decimal(q, out_fmt.rounding))
                res_fmt = out_fmt
            else:
                raw = int(_round_decimal(q, f1.rounding))
                res_fmt = FixedPointFormat(total_bits=f1.total_bits + f2.total_bits, frac_bits=frac,
                                           signed=True, endian=f1.endian, rounding=f1.rounding, saturate=True)
            raw = _saturate(raw, res_fmt) if res_fmt.saturate else raw
            return Fixed(raw, res_fmt)

        raise ValueError("unsupported op")

    def add(self, other: "Fixed", out_fmt: Optional[FixedPointFormat] = None) -> "Fixed":
        return self._binary_op(other, "add", out_fmt)

    def sub(self, other: "Fixed", out_fmt: Optional[FixedPointFormat] = None) -> "Fixed":
        return self._binary_op(other, "sub", out_fmt)

    def mul(self, other: "Fixed", out_fmt: Optional[FixedPointFormat] = None) -> "Fixed":
        return self._binary_op(other, "mul", out_fmt)

    def div(self, other: "Fixed", out_fmt: Optional[FixedPointFormat] = None) -> "Fixed":
        return self._binary_op(other, "div", out_fmt)

    # ---------- Утилиты ---------- #

    def rescale(self, target: FixedPointFormat) -> "Fixed":
        """
        Перевод в другой формат с заданным числом дробных бит.
        """
        # целевое целое = round(self.raw * 2^(target.frac - self.frac))
        shift = target.frac_bits - self.fmt.frac_bits
        if shift == 0:
            n = self.raw
        elif shift > 0:
            n = int(_round_decimal(Decimal(self.raw) * (Decimal(1) << shift), target.rounding))
        else:
            n = int(_round_decimal(Decimal(self.raw) / (Decimal(1) << (-shift)), target.rounding))
        if target.saturate:
            n = _saturate(n, target)
        else:
            _check_range(n, target)
        return Fixed(n, target)

    def __repr__(self) -> str:
        return f"Fixed(raw={self.raw}, fmt={self.fmt.q_notation()}, dec={str(self.to_decimal())})"

# ------------------------------ Высокоуровневые функции ------------------------------ #

def encode_decimal_to_fixed_bytes(d: Decimal, fmt: FixedPointFormat, with_crc32: bool = False) -> bytes:
    return Fixed.from_decimal(d, fmt).to_bytes(with_crc32=with_crc32)

def decode_fixed_bytes_to_decimal(data: bytes) -> Decimal:
    return Fixed.from_bytes(data).to_decimal()

def encode_floats_bulk(values: Iterable[float], fmt: FixedPointFormat) -> bytes:
    """
    Эффективная упаковка массива в компактный бинарный формат:
    [MAGIC 'FPX'][VER][count(varint)][header(fmt)][raw_stream ...]
    где raw_stream содержит слитые байты целочисленных представлений одинаковой длины.
    """
    vals = list(values)
    header = bytearray()
    header += MAGIC
    header.append(HEADER_VERSION)
    header += uleb128_encode(len(vals))

    # добавим описание формата как один экземпляр Fixed (без payload)
    tmp = Fixed.from_decimal(Decimal("0"), fmt).to_bytes(with_crc32=False)
    # tmp = H + varraw + raw(=all zeros). Обрежем raw_len + raw, оставим поля формата.
    # Найдём смещение varraw
    raw_len, off = uleb128_decode(tmp, 10)
    fmt_header = tmp[:10] + uleb128_encode(0)  # длина=0, без данных
    out = bytearray()
    out += header
    out += fmt_header

    # подготовим общий размер и пакуем
    raw_len_bytes = (fmt.total_bits + 7) // 8
    for f in vals:
        fx = Fixed.from_float(f, fmt)
        unsigned = _signed_to_twos_complement(fx.raw, fmt.total_bits) if fmt.signed else fx.raw
        out += int(unsigned).to_bytes(raw_len_bytes, byteorder=fmt.endian, signed=False)
    return bytes(out)

def decode_floats_bulk(data: bytes) -> List[float]:
    """
    Обратная операция к encode_floats_bulk.
    """
    if data[0:3] != MAGIC or data[3] != HEADER_VERSION:
        raise FixedPointFormatError("bad bulk header")
    count, off = uleb128_decode(data, 4)
    # восстановим fmt из "пустого" Fixed
    if data[off:off+3] != MAGIC:
        raise FixedPointFormatError("bad fmt header")
    ver = data[off+3]
    total_bits = data[off+4]
    frac_bits = data[off+5]
    flags = data[off+6]
    endian_b = data[off+7]
    rounding_b = data[off+8]
    options = data[off+9]
    off2 = off + 10
    raw_len, off3 = uleb128_decode(data, off2)
    if raw_len != 0:
        raise FixedPointFormatError("expected zero raw_len in bulk fmt")
    fmt = FixedPointFormat(
        total_bits=total_bits,
        frac_bits=frac_bits,
        signed=bool(flags & 0x01),
        endian="little" if endian_b == 0 else "big",
        rounding={0:"nearest_even",1:"nearest_away",2:"down",3:"up",4:"toward_zero"}[rounding_b],
        saturate=bool(options & 0x01),
        version=ver
    )
    pos = off3
    out: List[float] = []
    raw_len_bytes = (fmt.total_bits + 7) // 8
    for _ in range(count):
        chunk = data[pos:pos+raw_len_bytes]
        if len(chunk) != raw_len_bytes:
            raise FixedPointFormatError("truncated bulk payload")
        pos += raw_len_bytes
        raw = int.from_bytes(chunk, byteorder=fmt.endian, signed=False)
        if fmt.signed:
            raw = _twos_complement_to_signed(raw, fmt.total_bits)
        out.append(float(Decimal(raw) * fmt.scale))
    return out

# ------------------------------ Преднастройки форматов ------------------------------ #

# Частые пресеты
Q7_8  = FixedPointFormat(total_bits=16, frac_bits=8,  signed=True)   # диапазон [-128, 127.996...], шаг 1/256
Q15_16 = FixedPointFormat(total_bits=32, frac_bits=16, signed=True)  # аудио/DSP
UQ1_15 = FixedPointFormat(total_bits=16, frac_bits=15, signed=False) # [0, 1.999...]
Q23_8  = FixedPointFormat(total_bits=32, frac_bits=8,  signed=True)
UQ7_8  = FixedPointFormat(total_bits=16, frac_bits=8,  signed=False)

# ------------------------------ Самопроверка ------------------------------ #

if __name__ == "__main__":
    from decimal import Decimal as D

    def demo(fmt: FixedPointFormat, nums: Iterable[str]) -> None:
        print("Format:", fmt.q_notation(), "total_bits=", fmt.total_bits, "frac_bits=", fmt.frac_bits, "signed=", fmt.signed)
        for s in nums:
            d = D(s)
            fx = Fixed.from_decimal(d, fmt)
            b = fx.to_bytes(with_crc32=True)
            fx2 = Fixed.from_bytes(b)
            print(" ", s, "-> raw", fx.raw, "->", fx2.to_decimal())

    demo(Q7_8, ["0", "1", "-1", "12.75", "127.99609375"])
    # Пакетные операции
    arr = [0.0, 0.5, -0.5, 1.25]
    blob = encode_floats_bulk(arr, Q15_16)
    back = decode_floats_bulk(blob)
    print("bulk ok:", back)
