# chronowatch-core/chronowatch/utils/idgen.py
# SPDX-License-Identifier: Apache-2.0
"""
Промышленный модуль генерации идентификаторов для Chronowatch Core.

Возможности:
- ULID (Crockford Base32): ulid() и MonotonicULID (без коллизий внутри 1 ms, лексикографически сортируемые).
- Короткие криптостойкие ID: random_id()/random_id_base58()/random_id_base62().
- UUIDv4: uuid4_str() — для совместимости с экосистемой UUID.
- Snowflake64: компактные 64-битные ID (timestamp(ms) | node | sequence) с настраиваемым epoch,
  потокобезопасные, с декомпозицией и кодировками Base58/Base62.
- Базовые кодеки Base32 (Crockford), Base58 (Bitcoin alphabet), Base62.

Только стандартная библиотека: secrets, os, time, threading, datetime, uuid.
"""

from __future__ import annotations

import os
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Iterable, Optional, Tuple

__all__ = [
    # Время
    "now_ms",
    # ULID
    "ulid",
    "ulid_bytes",
    "MonotonicULID",
    # Короткие ID
    "random_id",
    "random_id_base58",
    "random_id_base62",
    # UUID
    "uuid4_str",
    # Snowflake64
    "SnowflakeGenerator",
    "SnowflakeParts",
    # Кодеки
    "b32_crockford_encode_128",
    "b58_encode",
    "b58_decode",
    "b62_encode",
    "b62_decode",
]

# ============================================================================
# Вспомогательное время
# ============================================================================

def now_ms() -> int:
    """Unix-время в миллисекундах (целое)."""
    return int(time.time() * 1000)


# ============================================================================
# Crockford Base32 для ULID
# ============================================================================

# Crockford Base32: без I, L, O, U
_B32_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_B32_LOOKUP: Dict[str, int] = {c: i for i, c in enumerate(_B32_ALPHABET)}
_B32_LOOKUP.update({c.lower(): i for c, i in _B32_LOOKUP.items()})


def b32_crockford_encode_128(value: int) -> str:
    """
    Кодирует 128-битное число в 26 символов Crockford Base32.
    ULID = 128 бит -> 26 символов (130 бит с ведущими нулями в представлении).
    """
    if value < 0 or value >> 128:
        raise ValueError("value must fit into 128 bits")
    chars = []
    for shift in range(25, -1, -1):
        idx = (value >> (shift * 5)) & 0b11111
        chars.append(_B32_ALPHABET[idx])
    return "".join(chars)


# ============================================================================
# ULID (Universally Unique Lexicographically Sortable Identifier)
#  - 48 бит времени (ms), 80 бит криптослучайной части
#  - Лексикографическая сортировка == сортировке по времени
# ============================================================================

def _ulid_pack(time_ms: int, rand80: int) -> int:
    if time_ms < 0 or time_ms >> 48:
        raise ValueError("time_ms must fit into 48 bits")
    if rand80 < 0 or rand80 >> 80:
        raise ValueError("rand80 must fit into 80 bits")
    return (time_ms << 80) | rand80


def ulid() -> str:
    """
    Генерирует ULID (26 символов Crockford Base32).
    Подходит для распределённых систем: сортируется по времени, криптостойкий хвост 80 бит.
    """
    t_ms = now_ms() & ((1 << 48) - 1)
    r80 = secrets.randbits(80)
    return b32_crockford_encode_128(_ulid_pack(t_ms, r80))


def ulid_bytes() -> bytes:
    """
    Возвращает ULID в 16 байтах (big-endian).
    """
    t_ms = now_ms() & ((1 << 48) - 1)
    r80 = secrets.randbits(80)
    v = _ulid_pack(t_ms, r80)
    return v.to_bytes(16, "big")


class MonotonicULID:
    """
    Монотонный ULID-генератор (без коллизий при множественных вызовах в один и тот же миллисекундный тик).
    Потокобезопасен. При переполнении случайной части «перескакивает» на следующий миллисекундный тик.

    Применение:
        m = MonotonicULID()
        s = m.new()       # строка ULID Base32
        b = m.new_bytes() # 16 байт
    """

    __slots__ = ("_lock", "_last_ms", "_last_rand")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last_ms = -1
        self._last_rand = 0

    def _next_int(self) -> int:
        with self._lock:
            t_ms = now_ms() & ((1 << 48) - 1)
            if t_ms != self._last_ms:
                self._last_ms = t_ms
                self._last_rand = secrets.randbits(80)
                return _ulid_pack(t_ms, self._last_rand)
            # тот же миллисекундный тик — увеличиваем 80-битную часть
            self._last_rand = (self._last_rand + 1) & ((1 << 80) - 1)
            if self._last_rand == 0:
                # переполнение — ждём следующую миллисекунду
                while True:
                    t2 = now_ms() & ((1 << 48) - 1)
                    if t2 != self._last_ms:
                        self._last_ms = t2
                        self._last_rand = secrets.randbits(80)
                        break
                    time.sleep(0.0001)
            return _ulid_pack(self._last_ms, self._last_rand)

    def new(self) -> str:
        return b32_crockford_encode_128(self._next_int())

    def new_bytes(self) -> bytes:
        return self._next_int().to_bytes(16, "big")


# ============================================================================
# UUIDv4 (случайный UUID)
# ============================================================================

def uuid4_str() -> str:
    """RFC 4122 UUIDv4, дефисный формат."""
    return str(uuid.uuid4())


# ============================================================================
# Короткие криптостойкие ID (NanoID-подобные)
# ============================================================================

# Bitcoin Base58 (без 0, O, I, l)
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_58 := _B58_ALPHABET)}

# Стандартное Base62
_B62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_B62_INDEX = {c: i for i, c in enumerate(_62 := _B62_ALPHABET)}


def random_id(size: int = 21, alphabet: str = _B62_ALPHABET) -> str:
    """
    Криптостойкий короткий ID. По умолчанию Base62-алфавит.
    """
    if size <= 0:
        raise ValueError("size must be > 0")
    return "".join(secrets.choice(alphabet) for _ in range(size))


def random_id_base58(size: int = 22) -> str:
    """Короткий ID на Bitcoin Base58 (удобно для ссылок)."""
    return random_id(size=size, alphabet=_B58_ALPHABET)


def random_id_base62(size: int = 21) -> str:
    """Короткий ID на Base62."""
    return random_id(size=size, alphabet=_B62_ALPHABET)


# ============================================================================
# Base58 / Base62 кодеки (для Snowflake и т.п.)
# ============================================================================

def b58_encode(n: int) -> str:
    """Кодирует неотрицательное целое в Base58 (Bitcoin alphabet)."""
    if n < 0:
        raise ValueError("n must be non-negative")
    if n == 0:
        return _B58_ALPHABET[0]
    out = []
    while n:
        n, rem = divmod(n, 58)
        out.append(_B58_ALPHABET[rem])
    return "".join(reversed(out))


def b58_decode(s: str) -> int:
    """Декодирует Base58 в целое."""
    val = 0
    for ch in s:
        try:
            val = val * 58 + _B58_INDEX[ch]
        except KeyError:
            raise ValueError(f"invalid base58 char: {ch!r}") from None
    return val


def b62_encode(n: int) -> str:
    """Кодирует неотрицательное целое в Base62."""
    if n < 0:
        raise ValueError("n must be non-negative")
    if n == 0:
        return _B62_ALPHABET[0]
    out = []
    while n:
        n, rem = divmod(n, 62)
        out.append(_B62_ALPHABET[rem])
    return "".join(reversed(out))


def b62_decode(s: str) -> int:
    """Декодирует Base62 в целое."""
    val = 0
    for ch in s:
        try:
            val = val * 62 + _B62_INDEX[ch]
        except KeyError:
            raise ValueError(f"invalid base62 char: {ch!r}") from None
    return val


# ============================================================================
# Snowflake64 — компактные 64-битные ID: [timestamp | node | sequence]
#  - 41 бит: время с кастомного epoch (ms)
#  - 10 бит: node_id (0..1023)
#  - 12 бит: sequence (0..4095) — инкремент в рамках одного ms
# Совместимо по идее с классической схемой, но epoch настраивается.
# ============================================================================

@dataclass(frozen=True)
class SnowflakeParts:
    timestamp_ms: int
    node_id: int
    sequence: int


class SnowflakeGenerator:
    """
    Потокобезопасный генератор 64-битных Snowflake-ID.

    Формат (ms_since_epoch << (NODE_BITS+SEQ_BITS)) | (node_id << SEQ_BITS) | sequence

    Аргументы:
      node_id:     0..(2^NODE_BITS-1)
      epoch:       datetime или int(ms). По умолчанию 2020-01-01T00:00:00Z.
      node_bits:   по умолчанию 10 (до 1024 узлов)
      seq_bits:    по умолчанию 12 (до 4096 ID/мс на узел)
    """

    def __init__(
        self,
        node_id: Optional[int] = None,
        *,
        epoch: Optional[int | datetime] = None,
        node_bits: int = 10,
        seq_bits: int = 12,
    ) -> None:
        if node_bits <= 0 or seq_bits <= 0 or node_bits + seq_bits >= 22 + 41:  # оставляем 41 бит под время
            raise ValueError("invalid bit allocation")
        self.NODE_BITS = node_bits
        self.SEQ_BITS = seq_bits
        self.MAX_NODE = (1 << node_bits) - 1
        self.MAX_SEQ = (1 << seq_bits) - 1

        if epoch is None:
            # Безопасный дефолт: 2020-01-01T00:00:00Z
            epoch_dt = datetime(2020, 1, 1, tzinfo=timezone.utc)
            self._epoch_ms = int(epoch_dt.timestamp() * 1000)
        elif isinstance(epoch, datetime):
            if epoch.tzinfo is None:
                raise ValueError("epoch datetime must be timezone-aware (UTC recommended)")
            self._epoch_ms = int(epoch.timestamp() * 1000)
        else:
            self._epoch_ms = int(epoch)

        if node_id is None:
            # Пытаемся взять из окружения, иначе криптослучайно (фиксируем в пределах диплоймента).
            node_env = os.getenv("CHRONOWATCH_NODE_ID")
            if node_env is not None:
                node_id = int(node_env)
            else:
                node_id = secrets.randbelow(self.MAX_NODE + 1)

        if not (0 <= node_id <= self.MAX_NODE):
            raise ValueError(f"node_id must be in [0, {self.MAX_NODE}]")
        self._node_id = int(node_id)

        self._lock = threading.Lock()
        self._last_ms = -1
        self._seq = 0

    # ----------------
    # Публичный API
    # ----------------
    def new_int(self) -> int:
        """
        Возвращает 64-битный Snowflake как целое.
        """
        with self._lock:
            ms = now_ms() - self._epoch_ms
            if ms < 0:
                ms = 0
            if ms == self._last_ms:
                self._seq = (self._seq + 1) & self.MAX_SEQ
                if self._seq == 0:
                    # Переполнение sequence в этом ms — ждём следующую миллисекунду.
                    while True:
                        cur = now_ms() - self._epoch_ms
                        if cur > ms:
                            ms = cur
                            break
                        time.sleep(0.0001)
            else:
                self._seq = 0
                self._last_ms = ms

            value = (ms << (self.NODE_BITS + self.SEQ_BITS)) | (self._node_id << self.SEQ_BITS) | self._seq
            return value & ((1 << 64) - 1)

    def new_str_base58(self) -> str:
        """Возвращает Snowflake в Base58."""
        return b58_encode(self.new_int())

    def new_str_base62(self) -> str:
        """Возвращает Snowflake в Base62."""
        return b62_encode(self.new_int())

    def decompose(self, value: int) -> SnowflakeParts:
        """Разбивает Snowflake на составные части (timestamp_ms от epoch, node_id, sequence)."""
        seq_mask = (1 << self.SEQ_BITS) - 1
        node_mask = ((1 << self.NODE_BITS) - 1) << self.SEQ_BITS

        sequence = value & seq_mask
        node_id = (value & node_mask) >> self.SEQ_BITS
        ts = value >> (self.NODE_BITS + self.SEQ_BITS)
        return SnowflakeParts(timestamp_ms=int(ts), node_id=int(node_id), sequence=int(sequence))

    # ----------------
    # Вспомогательные
    # ----------------
    @property
    def node_id(self) -> int:
        return self._node_id

    @property
    def epoch_ms(self) -> int:
        return self._epoch_ms
