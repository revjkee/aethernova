# mythos-core/mythos/utils/idgen.py
# -*- coding: utf-8 -*-
"""
Industrial ID generation utilities for Mythos Core.

Функции:
- UUID (v4, v7-like), ULID (монотоничный), Snowflake, KSUID, NanoID, short hash (BLAKE2b).
- Без внешних зависимостей. Потокобезопасность. Контроль дрейфа часов.
- Кодировки: Crockford Base32, Base58 (BTC), Base62.
- CLI: python idgen.py type [options]

Замечание:
- UUIDv7 реализован по текущей публичной спецификации (time-ordered layout)
  с установкой RFC4122-variant битов; это «v7-like» без зависимости от версий Python.
"""

from __future__ import annotations

import argparse
import os
import time
import threading
import secrets
import uuid as _uuid
import math
import hashlib
import typing as _t

# ============================================================
# Вспомогательные кодировки
# ============================================================

CROCKFORD32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # без I, L, O, U
BASE58_BTC = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def _encode_base_alphabet(b: bytes, alphabet: str) -> str:
    """Общее кодирование произвольной последовательности байт в строку заданного алфавита (base-N)."""
    if not b:
        return alphabet[0]
    # big-endian int
    num = int.from_bytes(b, "big")
    base = len(alphabet)
    chars = []
    while num > 0:
        num, rem = divmod(num, base)
        chars.append(alphabet[rem])
    # ведущие нули в байтах -> ведущие символы первого индекса алфавита
    pad = 0
    for byte in b:
        if byte == 0:
            pad += 1
        else:
            break
    return alphabet[0] * pad + "".join(reversed(chars))

def _decode_base_alphabet(s: str, alphabet: str, out_len: int | None = None) -> bytes:
    """Общее декодирование base-N строки в bytes."""
    if not s:
        return b""
    base = len(alphabet)
    idx = {c: i for i, c in enumerate(alphabet)}
    num = 0
    for ch in s:
        if ch not in idx:
            raise ValueError(f"invalid character '{ch}' for base{base}")
        num = num * base + idx[ch]
    # Подсчёт ведущих символов "нуля"
    pad = 0
    for ch in s:
        if ch == alphabet[0]:
            pad += 1
        else:
            break
    out = num.to_bytes((num.bit_length() + 7) // 8, "big")
    out = b"\x00" * pad + out
    if out_len is not None:
        # нормируем длину, дополняя слева нулями, если нужно
        if len(out) > out_len:
            raise ValueError("decoded length exceeds expected length")
        out = (b"\x00" * (out_len - len(out))) + out
    return out

def b32_crockford_encode(b: bytes) -> str:
    return _encode_base_alphabet(b, CROCKFORD32)

def b32_crockford_decode(s: str, out_len: int | None = None) -> bytes:
    # допустимы нижние регистры и смешанные
    s = s.upper().replace("O", "0").replace("I", "1").replace("L", "1")
    return _decode_base_alphabet(s, CROCKFORD32, out_len=out_len)

def b58_encode(b: bytes) -> str:
    return _encode_base_alphabet(b, BASE58_BTC)

def b58_decode(s: str, out_len: int | None = None) -> bytes:
    return _decode_base_alphabet(s, BASE58_BTC, out_len=out_len)

def b62_encode(b: bytes) -> str:
    return _encode_base_alphabet(b, BASE62)

def b62_decode(s: str, out_len: int | None = None) -> bytes:
    return _decode_base_alphabet(s, BASE62, out_len=out_len)

# ============================================================
# Время и монотоника
# ============================================================

_EPOCH_UNIX = 0  # для читаемости
_KSUID_EPOCH = 1400000000  # 2014-05-13 16:53:20 UTC (стандарт KSUID)
_DEFAULT_SNOWFLAKE_EPOCH = 1577836800000  # 2020-01-01 UTC в миллисекундах

def _now_ms() -> int:
    # Миллисекунды Unix
    return int(time.time() * 1000)

def _now_ns() -> int:
    return time.time_ns()

class _MonotonicMillis:
    """Гарантия неубывающего времени в миллисекундах для k-sortable ID."""
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last = 0

    def next(self, ts: int | None = None) -> int:
        with self._lock:
            now = _now_ms() if ts is None else ts
            if now <= self._last:
                # дрейф назад или тот же тик — двигаем на +1
                self._last = self._last + 1
            else:
                self._last = now
            return self._last

_MONO_MS = _MonotonicMillis()

# ============================================================
# ULID (Crockford Base32, 26 символов), с монотоникой
# ============================================================

class ULID:
    """ULID: 128 бит = 48 бит времени (ms) + 80 бит энтропии. Строка 26 char Base32 Crockford."""
    @staticmethod
    def new(monotonic: bool = True) -> str:
        # время
        ts = _MONO_MS.next() if monotonic else _now_ms()
        # 80 бит энтропии
        rand = secrets.token_bytes(10)
        # 48-битный ts big-endian + 80-битная энтропия
        ts_bytes = ts.to_bytes(6, "big")
        ulid_bytes = ts_bytes + rand
        return b32_crockford_encode(ulid_bytes)

    @staticmethod
    def to_bytes(ulid_str: str) -> bytes:
        b = b32_crockford_decode(ulid_str, out_len=16)
        if len(b) != 16:
            raise ValueError("invalid ULID length")
        return b

    @staticmethod
    def from_bytes(b: bytes) -> str:
        if len(b) != 16:
            raise ValueError("invalid ULID bytes length")
        return b32_crockford_encode(b)

    @staticmethod
    def timestamp_ms(ulid_str: str) -> int:
        b = ULID.to_bytes(ulid_str)
        return int.from_bytes(b[0:6], "big")

# ============================================================
# UUID v4 и v7-like (RFC4122 variant)
# ============================================================

def uuid_v4() -> str:
    return str(_uuid.uuid4())

def uuid_v7_like() -> str:
    """
    UUIDv7-like: 48 бит unix_ms | ver=7 | 12 бит rand_a | variant RFC4122 | 62 бит rand_b
    """
    ts_ms = _MONO_MS.next()
    rand_a = secrets.randbits(12)
    rand_b = secrets.randbits(62)

    # Конструируем 128-битное число
    # Старшие 48 бит времени
    hi = (ts_ms & ((1 << 48) - 1)) << 16
    # Версия (4 бита): 0b0111
    hi |= (7 << 12)
    # 12 бит rand_a
    hi |= (rand_a & 0xFFF)

    # Нижние 64 бита: variant (RFC4122: 0b10xx) в старших двух битах + 62 бита rand_b
    lo = (0b10 << 62) | (rand_b & ((1 << 62) - 1))

    val = (hi << 64) | lo
    return str(_uuid.UUID(int=val))

# ============================================================
# Snowflake (64-bit)
# ============================================================

class SnowflakeGenerator:
    """
    Классический Snowflake: 1 бит — знак (0), timestamp, datacenter, worker, sequence.
    По умолчанию: 41 бит времени (ms since epoch) + 5 + 5 + 12.
    """
    def __init__(self, epoch_ms: int = _DEFAULT_SNOWFLAKE_EPOCH,
                 datacenter_id: int = 0, worker_id: int = 0,
                 bits_timestamp: int = 41, bits_datacenter: int = 5,
                 bits_worker: int = 5, bits_sequence: int = 12) -> None:
        self.epoch = epoch_ms
        self.bits_timestamp = bits_timestamp
        self.bits_datacenter = bits_datacenter
        self.bits_worker = bits_worker
        self.bits_sequence = bits_sequence

        self.max_datacenter = (1 << bits_datacenter) - 1
        self.max_worker = (1 << bits_worker) - 1
        self.max_sequence = (1 << bits_sequence) - 1

        if not (0 <= datacenter_id <= self.max_datacenter):
            raise ValueError("datacenter_id out of range")
        if not (0 <= worker_id <= self.max_worker):
            raise ValueError("worker_id out of range")

        self.datacenter_id = datacenter_id
        self.worker_id = worker_id

        self._lock = threading.Lock()
        self._last_ms = -1
        self._sequence = 0

    def _wait_next_ms(self, last_ms: int) -> int:
        cur = _now_ms()
        while cur <= last_ms:
            # очень короткий сон, чтобы перейти на следующий тик миллисекунды
            time.sleep(0.0001)
            cur = _now_ms()
        return cur

    def new(self) -> int:
        with self._lock:
            cur_ms = _now_ms()
            if cur_ms < self._last_ms:
                # часы ушли назад — fallback на монотонику
                cur_ms = _MONO_MS.next(self._last_ms)

            if cur_ms == self._last_ms:
                self._sequence = (self._sequence + 1) & self.max_sequence
                if self._sequence == 0:
                    cur_ms = self._wait_next_ms(self._last_ms)
            else:
                self._sequence = 0

            self._last_ms = cur_ms

            ts_part = cur_ms - self.epoch
            if ts_part < 0:
                # на случай неверной epoch
                ts_part = 0

            # Сборка 64-битного ID
            id_ = ((ts_part & ((1 << self.bits_timestamp) - 1)) << (self.bits_datacenter + self.bits_worker + self.bits_sequence))
            id_ |= (self.datacenter_id & self.max_datacenter) << (self.bits_worker + self.bits_sequence)
            id_ |= (self.worker_id & self.max_worker) << self.bits_sequence
            id_ |= (self._sequence & self.max_sequence)
            return id_

    @staticmethod
    def to_str(id_: int, base: str = "b58") -> str:
        b = id_.to_bytes(8, "big")
        if base == "b58":
            return b58_encode(b).lstrip("1")  # убираем лидирующие нули для компактности
        if base == "b62":
            return b62_encode(b).lstrip("0")
        if base == "b32":
            return b32_crockford_encode(b).lstrip("0")
        return str(id_)

# ============================================================
# KSUID (27 символов Base62, 20 байт: 4 ts + 16 random)
# ============================================================

class KSUID:
    @staticmethod
    def new() -> str:
        ts = int(time.time()) - _KSUID_EPOCH
        if ts < 0:
            ts = 0
        ts_b = ts.to_bytes(4, "big")
        payload = secrets.token_bytes(16)
        raw = ts_b + payload  # 20 байт
        return b62_encode(raw).rjust(27, "0")  # стандартная длина 27

    @staticmethod
    def to_bytes(s: str) -> bytes:
        b = b62_decode(s, out_len=20)
        if len(b) != 20:
            raise ValueError("invalid KSUID length")
        return b

# ============================================================
# NanoID (по умолчанию 21 символ, алфавит по spec)
# ============================================================

_NANO_DEFAULT_ALPHABET = "_-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

def nanoid(size: int = 21, alphabet: str = _NANO_DEFAULT_ALPHABET) -> str:
    if size <= 0:
        raise ValueError("size must be > 0")
    if not alphabet or len(set(alphabet)) != len(alphabet):
        raise ValueError("alphabet must be unique non-empty characters")
    return "".join(secrets.choice(alphabet) for _ in range(size))

# ============================================================
# Короткие хэши и универсальные функции
# ============================================================

def short_hash(data: bytes | str, length: int = 16, base: str = "b58") -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    h = hashlib.blake2b(data, digest_size=32).digest()
    raw = h[:max(4, min(length, len(h)))]
    if base == "b58":
        return b58_encode(raw)
    if base == "b62":
        return b62_encode(raw)
    if base == "b32":
        return b32_crockford_encode(raw)
    return raw.hex()

# ============================================================
# Фасад
# ============================================================

class IDGen:
    """Единая точка входа для генерации ID."""
    def __init__(self,
                 snowflake_epoch_ms: int = int(os.environ.get("MYTHOS_SNOWFLAKE_EPOCH_MS", _DEFAULT_SNOWFLAKE_EPOCH)),
                 datacenter_id: int = int(os.environ.get("MYTHOS_DC_ID", "0")),
                 worker_id: int = int(os.environ.get("MYTHOS_WORKER_ID", "0"))) -> None:
        self.snowflake = SnowflakeGenerator(epoch_ms=snowflake_epoch_ms,
                                            datacenter_id=datacenter_id,
                                            worker_id=worker_id)

    # Строковые ID
    def ulid(self) -> str:
        return ULID.new(monotonic=True)

    def uuid4(self) -> str:
        return uuid_v4()

    def uuid7(self) -> str:
        return uuid_v7_like()

    def ksuid(self) -> str:
        return KSUID.new()

    def nanoid(self, size: int = 21, alphabet: str = _NANO_DEFAULT_ALPHABET) -> str:
        return nanoid(size=size, alphabet=alphabet)

    def snowflake_str(self, base: str = "b58") -> str:
        return SnowflakeGenerator.to_str(self.snowflake.new(), base=base)

    # Числовой Snowflake
    def snowflake_int(self) -> int:
        return self.snowflake.new()

    # Хэш
    def shash(self, data: bytes | str, length: int = 16, base: str = "b58") -> str:
        return short_hash(data, length=length, base=base)

# ============================================================
# CLI
# ============================================================

def _cli() -> int:
    p = argparse.ArgumentParser(description="Mythos ID Generator CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("ulid", help="Generate ULID")
    sub.add_parser("uuid4", help="Generate UUIDv4")
    sub.add_parser("uuid7", help="Generate UUIDv7-like")
    sub.add_parser("ksuid", help="Generate KSUID")

    sp_sf = sub.add_parser("snowflake", help="Generate Snowflake")
    sp_sf.add_argument("--int", action="store_true", help="return integer instead of string")
    sp_sf.add_argument("--base", choices=["b58", "b62", "b32", "dec"], default="b58")

    sp_nid = sub.add_parser("nanoid", help="Generate NanoID")
    sp_nid.add_argument("--size", type=int, default=21)
    sp_nid.add_argument("--alphabet", type=str, default=_NANO_DEFAULT_ALPHABET)

    sp_sh = sub.add_parser("shash", help="Short hash (BLAKE2b)")
    sp_sh.add_argument("--data", type=str, required=True)
    sp_sh.add_argument("--length", type=int, default=16)
    sp_sh.add_argument("--base", choices=["b58", "b62", "b32", "hex"], default="b58")

    sp_chk = sub.add_parser("decode", help="Decode helpers")
    sp_chk.add_argument("--base", choices=["b58", "b62", "b32"], required=True)
    sp_chk.add_argument("--value", required=True)
    sp_chk.add_argument("--out-len", type=int, default=None)

    args = p.parse_args()
    gen = IDGen()

    if args.cmd == "ulid":
        print(gen.ulid()); return 0
    if args.cmd == "uuid4":
        print(gen.uuid4()); return 0
    if args.cmd == "uuid7":
        print(gen.uuid7()); return 0
    if args.cmd == "ksuid":
        print(gen.ksuid()); return 0
    if args.cmd == "snowflake":
        if args.int:
            print(gen.snowflake_int()); return 0
        s = gen.snowflake_str(base=args.base)
        print(s); return 0
    if args.cmd == "nanoid":
        print(gen.nanoid(size=args.size, alphabet=args.alphabet)); return 0
    if args.cmd == "shash":
        print(gen.shash(args.data, length=args.length, base=args.base)); return 0
    if args.cmd == "decode":
        if args.base == "b58":
            b = b58_decode(args.value, out_len=args.out_len)
        elif args.base == "b62":
            b = b62_decode(args.value, out_len=args.out_len)
        else:
            b = b32_crockford_decode(args.value, out_len=args.out_len)
        print(b.hex()); return 0

    return 1

# ============================================================
# Пример использования в коде
# ============================================================

def example_usage() -> None:
    gen = IDGen(datacenter_id=1, worker_id=7)
    print("ULID:", gen.ulid())
    print("UUID4:", gen.uuid4())
    print("UUID7-like:", gen.uuid7())
    print("KSUID:", gen.ksuid())
    print("Snowflake int:", gen.snowflake_int())
    print("Snowflake b58:", gen.snowflake_str("b58"))
    print("NanoID:", gen.nanoid())
    print("ShortHash b58:", gen.shash("mythos-core", length=12, base="b58"))

if __name__ == "__main__":
    raise SystemExit(_cli())
