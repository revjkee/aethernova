# path: omnimind-core/omnimind/utils/idgen.py
# License: MIT
"""
Промышленный генератор идентификаторов:
- ULID (Crockford Base32, монотоничный в пределах процесса, 26-символьная строка)
- UUIDv7 (времясортируемый UUID по проекту draft-peabody-uuidv7, 36-символьная строка)
- Snowflake64 (настраиваемый 64-битный целочисленный ID + base62-представление)

Особенности:
- Потокобезопасно (threading.Lock), без внешних зависимостей
- Монотоничные ULID (при одинаковом timestamp инкрементируется рандомная часть)
- UUIDv7 собирается вручную: 48 бит мс-таймстамп, версия = 7, вариант RFC 4122
- Snowflake: эпоха/биты/узел конфигурируемы через окружение
- Кодировки: Crockford Base32 (ULID), Base62 (числа Snowflake)
- Защита: ожидание следующей миллисекунды при переполнении последовательности, ожидание при clock-skew

Окружение (опционально):
- OMNI_SNOWFLAKE_EPOCH_MS: кастомная эпоха (мс, по умолчанию 2020-01-01T00:00:00Z)
- OMNI_SNOWFLAKE_DC, OMNI_SNOWFLAKE_WORKER: идентификаторы площадки/воркера
"""

from __future__ import annotations

import os
import time
import uuid
import hmac
import math
import socket
import struct
import hashlib
import threading
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Tuple

# =========================
# Вспомогательные функции
# =========================

def _utc_ms() -> int:
    # wall-clock мс с защитой от отрицательных значений
    return max(0, int(time.time() * 1000))

def _sleep_ms(ms: int) -> None:
    time.sleep(max(0.0, ms / 1000.0))

def _hostname_fingerprint() -> int:
    try:
        name = socket.gethostname().encode("utf-8", "ignore")
    except Exception:
        name = b"unknown-host"
    h = hashlib.sha256(name).digest()
    return struct.unpack(">I", h[:4])[0]

def _process_fingerprint() -> int:
    try:
        pid = os.getpid()
    except Exception:
        pid = 0
    h = hashlib.sha256(str(pid).encode()).digest()
    return struct.unpack(">I", h[:4])[0]

# =========================
# Crockford Base32 (ULID)
# =========================

_B32_ALPH = "0123456789ABCDEFGHJKMNPQRSTUVWXYZ"  # без I, L, O, U
_B32_MAP = {c: i for i, c in enumerate(_B32_ALPH)}
_B32_LOWER_MAP = {c.lower(): i for c, i in _B32_MAP.items()}

def _b32_encode_ulid(data: bytes) -> str:
    """Кодирует 16 байт ULID в 26 символов Crockford Base32."""
    if len(data) != 16:
        raise ValueError("ULID requires exactly 16 bytes")
    n = int.from_bytes(data, "big")
    chars = []
    for _ in range(26):
        n, rem = divmod(n, 32)
        chars.append(_B32_ALPH[rem])
    return "".join(reversed(chars))

def _b32_decode_ulid(s: str) -> bytes:
    """Декодирует 26-символьный ULID в 16 байт."""
    if len(s) != 26:
        raise ValueError("ULID string must be 26 chars")
    n = 0
    for ch in s:
        if ch in _B32_MAP:
            v = _B32_MAP[ch]
        else:
            v = _B32_LOWER_MAP.get(ch)
            if v is None:
                raise ValueError(f"invalid ULID character: {ch!r}")
        n = (n * 32) + v
    return n.to_bytes(16, "big")

# =========================
# Base62 (для Snowflake/интов)
# =========================

_B62_ALPH = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_B62_MAP = {c: i for i, c in enumerate(_B62_ALPH)}

def base62_encode(n: int) -> str:
    if n < 0:
        raise ValueError("base62 encodes non-negative integers only")
    if n == 0:
        return "0"
    chars = []
    while n:
        n, rem = divmod(n, 62)
        chars.append(_B62_ALPH[rem])
    return "".join(reversed(chars))

def base62_decode(s: str) -> int:
    n = 0
    for ch in s:
        if ch not in _B62_MAP:
            raise ValueError(f"invalid base62 character: {ch!r}")
        n = n * 62 + _B62_MAP[ch]
    return n

# =========================
# ULID монотоничный
# =========================

class ULID:
    """
    128-битный ULID: 48 бит мс-таймстамп + 80 бит энтропии.
    Лексикографически и по времени сортируется, монотоничность внутри процесса.
    """
    __slots__ = ("_lock", "_last_ms", "_last_rand")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last_ms = -1
        self._last_rand = 0

    def new(self) -> str:
        """
        Возвращает 26-символьную строку ULID (Crockford Base32).
        """
        with self._lock:
            now_ms = _utc_ms()
            if now_ms > self._last_ms:
                self._last_ms = now_ms
                # 80-битная энтропия
                self._last_rand = secrets.randbits(80)
            else:
                # та же или меньшая мс-отметка => инкрементируем энтропию для монотоничности
                self._last_rand = (self._last_rand + 1) & ((1 << 80) - 1)
                if now_ms < self._last_ms:
                    # Часы откачены назад — придерживаемся последнего значения времени
                    now_ms = self._last_ms

            ts = self._last_ms & ((1 << 48) - 1)
            rand80 = self._last_rand
            n = (ts << 80) | rand80
            data = n.to_bytes(16, "big")
            return _b32_encode_ulid(data)

    @staticmethod
    def to_bytes(ulid_str: str) -> bytes:
        return _b32_decode_ulid(ulid_str)

    @staticmethod
    def from_bytes(data: bytes) -> str:
        return _b32_encode_ulid(data)

# =========================
# UUIDv7 (времясортируемый)
# =========================

class UUIDv7:
    """
    Формирует UUIDv7 согласно проекту спецификации:
    - 48 бит: миллисекунды Unix epoch
    - 4 бита: версия (0b0111)
    - 12 бит: random_a
    - 2 бита: variant (RFC 4122 = 0b10)
    - 62 бита: random_b
    """
    __slots__ = ()

    def new(self) -> uuid.UUID:
        ms = _utc_ms() & ((1 << 48) - 1)
        rand_a = secrets.randbits(12)
        rand_b = secrets.randbits(62)
        val = (
            (ms << 80) |
            (0x7 << 76) |
            (rand_a << 64) |
            (0b10 << 62) |
            rand_b
        )
        return uuid.UUID(int=val)

    def new_str(self) -> str:
        return str(self.new())

# =========================
# Snowflake64 (64-бит, настраиваемый)
# =========================

@dataclass
class SnowflakeConfig:
    epoch_ms: int
    datacenter_bits: int = 5
    worker_bits: int = 5
    sequence_bits: int = 12

    @property
    def max_datacenter(self) -> int:
        return (1 << self.datacenter_bits) - 1

    @property
    def max_worker(self) -> int:
        return (1 << self.worker_bits) - 1

    @property
    def max_sequence(self) -> int:
        return (1 << self.sequence_bits) - 1

    @property
    def ts_shift(self) -> int:
        return self.datacenter_bits + self.worker_bits + self.sequence_bits

    @property
    def dc_shift(self) -> int:
        return self.worker_bits + self.sequence_bits

    @property
    def worker_shift(self) -> int:
        return self.sequence_bits

class Snowflake64:
    """
    64-битный ID: [timestamp | datacenter | worker | sequence]
    - timestamp: мс с кастомной эпохи
    - ожидание при переполнении sequence в пределах миллисекунды
    - защита от clock-skew: ожидание пока wall-clock >= последней метки
    """
    __slots__ = ("cfg", "dc", "worker", "_lock", "_last_ms", "_seq")

    def __init__(self, cfg: Optional[SnowflakeConfig] = None,
                 datacenter_id: Optional[int] = None, worker_id: Optional[int] = None) -> None:
        if cfg is None:
            epoch_env = os.getenv("OMNI_SNOWFLAKE_EPOCH_MS")
            if epoch_env and epoch_env.isdigit():
                epoch_ms = int(epoch_env)
            else:
                # 2020-01-01T00:00:00Z
                epoch_ms = int(datetime(2020, 1, 1, tzinfo=timezone.utc).timestamp() * 1000)
            cfg = SnowflakeConfig(epoch_ms=epoch_ms)

        # Вычислим стабильные ID, если не заданы явно
        if datacenter_id is None:
            env_dc = os.getenv("OMNI_SNOWFLAKE_DC")
            datacenter_id = int(env_dc) if env_dc and env_dc.isdigit() else (_hostname_fingerprint() & cfg.max_datacenter)
        if worker_id is None:
            env_w = os.getenv("OMNI_SNOWFLAKE_WORKER")
            worker_id = int(env_w) if env_w and env_w.isdigit() else ((_process_fingerprint() ^ _hostname_fingerprint()) & cfg.max_worker)

        if not (0 <= datacenter_id <= cfg.max_datacenter):
            raise ValueError(f"datacenter_id out of range 0..{cfg.max_datacenter}")
        if not (0 <= worker_id <= cfg.max_worker):
            raise ValueError(f"worker_id out of range 0..{cfg.max_worker}")

        self.cfg = cfg
        self.dc = datacenter_id
        self.worker = worker_id
        self._lock = threading.Lock()
        self._last_ms = -1
        self._seq = 0

    def new_int(self) -> int:
        with self._lock:
            now_ms = _utc_ms()
            # защита от назад идущих часов
            if now_ms < self._last_ms:
                _sleep_ms(self._last_ms - now_ms)
                now_ms = _utc_ms()

            if now_ms == self._last_ms:
                self._seq = (self._seq + 1) & self.cfg.max_sequence
                if self._seq == 0:
                    # переполнение — ждём следующую мс
                    while now_ms <= self._last_ms:
                        now_ms = _utc_ms()
            else:
                self._seq = 0

            self._last_ms = now_ms
            ts_part = (now_ms - self.cfg.epoch_ms) & ((1 << (64 - self.cfg.ts_shift)) - 1)
            val = (
                (ts_part << self.cfg.ts_shift) |
                (self.dc << self.cfg.dc_shift) |
                (self.worker << self.cfg.worker_shift) |
                self._seq
            )
            return val

    def new_str62(self) -> str:
        return base62_encode(self.new_int())

# =========================
# Высокоуровневое API
# =========================

_ulid_gen = ULID()
_uuid7_gen = UUIDv7()
_snowflake_gen = Snowflake64()  # использует окружение по умолчанию

def new_ulid() -> str:
    """26-символьный ULID (Crockford Base32)."""
    return _ulid_gen.new()

def new_uuid7() -> str:
    """Строка UUIDv7 (36 символов, canonical)."""
    return _uuid7_gen.new_str()

def new_snowflake_int() -> int:
    """64-битное целое Snowflake."""
    return _snowflake_gen.new_int()

def new_snowflake_str() -> str:
    """Base62-представление Snowflake (URL-safe)."""
    return _snowflake_gen.new_str62()

# =========================
# Парсинг/помощники
# =========================

def is_ulid(s: str) -> bool:
    if len(s) != 26:
        return False
    try:
        _b32_decode_ulid(s)
        return True
    except Exception:
        return False

def is_uuid(s: str) -> bool:
    try:
        uuid.UUID(s)
        return True
    except Exception:
        return False

def is_snowflake62(s: str) -> bool:
    try:
        n = base62_decode(s)
        return n >= 0
    except Exception:
        return False

# =========================
# Самопроверка (doctest-стиль)
# =========================

if __name__ == "__main__":
    # Быстрый smoke-test
    u1, u2 = new_ulid(), new_ulid()
    print("ULID:", u1, u2, "lex_ok:", u1 < u2)
    v7 = new_uuid7()
    print("UUIDv7:", v7, "is_uuid:", is_uuid(v7))
    sf_int = new_snowflake_int()
    sf_str = base62_encode(sf_int)
    print("Snowflake:", sf_int, sf_str, "roundtrip:", base62_decode(sf_str) == sf_int)
