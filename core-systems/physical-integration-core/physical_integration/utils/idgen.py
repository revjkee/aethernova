# physical-integration-core/physical_integration/utils/idgen.py
from __future__ import annotations

import os
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Tuple

__all__ = [
    "uuid4_str",
    "ulid",
    "ulid_bytes",
    "ulid_to_datetime",
    "is_ulid",
    "MonotonicULID",
    "Snowflake",
    "base58_encode",
    "base62_encode",
    "with_prefix",
]

# ========================== Общие утилиты времени ==========================

def _now_ms() -> int:
    """Текущее время в миллисекундах (Unix epoch), монотонично по возможности."""
    # time.time_ns() — высокоточный источник. Монотоничность на уровне ОС не гарантирована,
    # поэтому компенсируем на уровне генераторов (lock + last_ts).
    return time.time_ns() // 1_000_000


# ========================== Crockford Base32 для ULID ======================

# Алфавит ULID (Crockford), без I, L, O, U
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CROCKFORD_INV = {c: i for i, c in enumerate(_CROCKFORD)}

def _b32c_encode(data: bytes) -> str:
    """Crockford Base32 без паддинга."""
    out = []
    bits = 0
    acc = 0
    for b in data:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            idx = (acc >> (bits - 5)) & 0b11111
            out.append(_CROCKFORD[idx])
            bits -= 5
    if bits:
        idx = (acc << (5 - bits)) & 0b11111
        out.append(_CROCKFORD[idx])
    return "".join(out)

def _b32c_decode(s: str) -> bytes:
    """Обратное преобразование Crockford Base32 (для частичного парсинга ULID)."""
    s = s.strip().upper()
    acc = 0
    bits = 0
    out = bytearray()
    for ch in s:
        if ch not in _CROCKFORD_INV:
            raise ValueError("invalid Crockford Base32")
        acc = (acc << 5) | _CROCKFORD_INV[ch]
        bits += 5
        if bits >= 8:
            out.append((acc >> (bits - 8)) & 0xFF)
            bits -= 8
    return bytes(out)


# ========================== ULID (универсальный, сортируемый) ==============

# Структура ULID: 48 бит времени (мс) + 80 бит случайности = 128 бит (16 байт) -> 26 символов Base32
# Лексикографическая сортировка строковых ULID соответствует возрастанию времени.

def ulid_bytes(ts_ms: Optional[int] = None, rand10: Optional[bytes] = None) -> bytes:
    """
    Сформировать сырые 16 байт ULID.
    ts_ms: время в мс (по умолчанию текущее), 0 <= ts < 2^48
    rand10: 10 байт криптослучайности (по умолчанию secrets.token_bytes(10))
    """
    if ts_ms is None:
        ts_ms = _now_ms()
    if not (0 <= ts_ms < (1 << 48)):
        raise ValueError("ts_ms out of range for ULID (48 bits)")
    if rand10 is None:
        rand10 = secrets.token_bytes(10)
    if len(rand10) != 10:
        raise ValueError("rand10 must be exactly 10 bytes")
    # 6 байт времени (big-endian), 10 байт случайности
    time6 = ts_ms.to_bytes(6, "big")
    return time6 + rand10

def ulid(ts_ms: Optional[int] = None) -> str:
    """
    Строковый ULID (26 символов Crockford Base32, без паддинга).
    """
    raw = ulid_bytes(ts_ms=ts_ms)
    return _b32c_encode(raw)

def ulid_to_datetime(u: str) -> datetime:
    """
    Извлечь отметку времени из ULID (первые 48 бит) и вернуть UTC datetime.
    """
    if not is_ulid(u):
        raise ValueError("invalid ULID")
    # первые 10 символов Base32 содержат ~50 бит, нам нужны 48 бит => декодируем всё и берём первые 6 байт
    raw = _b32c_decode(u)  # вернёт 16 байт
    if len(raw) < 6:
        raise ValueError("invalid ULID raw length")
    ts_ms = int.from_bytes(raw[:6], "big")
    return datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)

def is_ulid(s: str) -> bool:
    """Быстрая проверка валидности ULID (длина и алфавит)."""
    if not isinstance(s, str) or len(s) != 26:
        return False
    up = s.upper()
    return all(ch in _CROCKFORD_INV for ch in up)


class MonotonicULID:
    """
    Потокобезопасный монотоничный ULID-генератор.
    Гарантирует строгую возрастание ULID в пределах одинакового миллисекундного таймстемпа.
    При переполнении случайной части ожидает следующую миллисекунду.
    """
    __slots__ = ("_lock", "_last_ts", "_last_rand_int")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last_ts: int = -1
        self._last_rand_int: int = -1  # 80-битная случайность как int

    def generate(self, ts_ms: Optional[int] = None) -> str:
        """
        Вернуть строковый ULID (26 символов).
        """
        with self._lock:
            now_ts = _now_ms() if ts_ms is None else ts_ms
            if now_ts < self._last_ts:
                # Часы "откатились": используем последний известный ts (moнoтoничность важнее)
                now_ts = self._last_ts

            if now_ts != self._last_ts:
                # новая миллисекунда — новая случайность
                self._last_ts = now_ts
                self._last_rand_int = int.from_bytes(secrets.token_bytes(10), "big")
            else:
                # та же миллисекунда — инкрементируем 80-битную часть
                self._last_rand_int = (self._last_rand_int + 1) & ((1 << 80) - 1)
                if self._last_rand_int == 0:
                    # переполнение — ждём следующую миллисекунду
                    target = self._last_ts + 1
                    while _now_ms() < target:
                        time.sleep(0.0001)  # 100 µs бэк-офф
                    self._last_ts = target
                    self._last_rand_int = int.from_bytes(secrets.token_bytes(10), "big")

            raw = self._last_ts.to_bytes(6, "big") + self._last_rand_int.to_bytes(10, "big")
            return _b32c_encode(raw)


# ========================== UUIDv4 (случайный, RFC4122) =====================

def uuid4_str() -> str:
    """Строковый UUIDv4."""
    return str(uuid.uuid4())


# ========================== Snowflake-совместимый генератор ==================

@dataclass
class SnowflakeConfig:
    """
    Конфигурация Snowflake-ID:
      time_bits:    биты для таймстемпа (мс от epoch_ms)
      node_bits:    биты для узла (datacenter+worker) или просто worker
      seq_bits:     биты счётчика в пределах одной мс
      epoch_ms:     пользовательская эпоха (по умолчанию 2020-01-01T00:00:00Z)
      spin_on_clock_back_ms: сколько миллисекунд максимально ждать при обратном ходе часов
    """
    time_bits: int = 41
    node_bits: int = 10
    seq_bits: int = 12
    epoch_ms: int = int(datetime(2020, 1, 1, tzinfo=timezone.utc).timestamp() * 1000)
    spin_on_clock_back_ms: int = 5  # мягкая защита от «скачков» назад

class Snowflake:
    """
    Потокобезопасный генератор Snowflake-ID (целое число) с методами короткого представления.
    """
    __slots__ = ("cfg", "node_id", "_lock", "_last_ts", "_seq", "_max_seq")

    def __init__(self, node_id: int, cfg: Optional[SnowflakeConfig] = None) -> None:
        self.cfg = cfg or SnowflakeConfig()
        if node_id < 0 or node_id >= (1 << self.cfg.node_bits):
            raise ValueError("node_id out of range for configured node_bits")

        self.node_id = node_id
        self._lock = threading.Lock()
        self._last_ts = -1
        self._seq = 0
        self._max_seq = (1 << self.cfg.seq_bits) - 1

    def next_int(self) -> int:
        """
        Вернуть следующий Snowflake-ID как целое число.
        """
        with self._lock:
            now = _now_ms()
            # Компенсация обратного хода часов
            if now < self._last_ts:
                # ждём, но не бесконечно
                delta = min(self.cfg.spin_on_clock_back_ms, self._last_ts - now)
                end = time.time() + (delta / 1000.0)
                while _now_ms() < self._last_ts and time.time() < end:
                    time.sleep(0.0001)
                now = max(now, _now_ms(), self._last_ts)

            if now == self._last_ts:
                self._seq = (self._seq + 1) & self._max_seq
                if self._seq == 0:
                    # переполнение последовательности — ждём следующую миллисекунду
                    target = now + 1
                    while _now_ms() < target:
                        time.sleep(0.0001)
                    now = target
            else:
                self._seq = 0

            self._last_ts = now

            # Битовая раскладка: [timestamp | node | sequence]
            t = (now - self.cfg.epoch_ms) & ((1 << self.cfg.time_bits) - 1)
            n = self.node_id & ((1 << self.cfg.node_bits) - 1)
            s = self._seq & ((1 << self.cfg.seq_bits) - 1)

            return (t << (self.cfg.node_bits + self.cfg.seq_bits)) | (n << self.cfg.seq_bits) | s

    def next_base58(self) -> str:
        """Короткая Base58-строка (без символов, похожих на 0/O/I/l)."""
        return base58_encode(self.next_int())

    def next_base62(self) -> str:
        """Короткая Base62-строка (0-9A-Za-z)."""
        return base62_encode(self.next_int())


# ========================== Короткие кодировки ===============================

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def base58_encode(n: int) -> str:
    """Кодировать неотрицательное целое в Base58 (Bitcoin alphabet)."""
    if n < 0:
        raise ValueError("n must be non-negative")
    if n == 0:
        return _B58_ALPHABET[0]
    out = []
    base = 58
    while n:
        n, r = divmod(n, base)
        out.append(_B58_ALPHABET[r])
    return "".join(reversed(out))

def base62_encode(n: int) -> str:
    """Кодировать неотрицательное целое в Base62 (0-9A-Za-z)."""
    if n < 0:
        raise ValueError("n must be non-negative")
    if n == 0:
        return _B62_ALPHABET[0]
    out = []
    base = 62
    while n:
        n, r = divmod(n, base)
        out.append(_B62_ALPHABET[r])
    return "".join(reversed(out))


# ========================== Префиксы для доменных ключей =====================

def with_prefix(prefix: str, id_str: str, sep: str = "_") -> str:
    """
    Добавить стабильный префикс к идентификатору.
    Пример: with_prefix("dev", ulid()) -> "dev_01H...".
    """
    if not prefix:
        return id_str
    return f"{prefix}{sep}{id_str}"


# ========================== Примеры/демо (не исполняется при импорте) ========

if __name__ == "__main__":
    # Пример использования:
    print("UUIDv4:", uuid4_str())

    mono = MonotonicULID()
    u1 = mono.generate()
    u2 = mono.generate()
    print("ULID (monotonic):", u1, u2, "sorted:", u1 < u2)

    print("ULID -> datetime:", ulid_to_datetime(u1))

    sf = Snowflake(node_id=42)
    s1 = sf.next_int()
    s2 = sf.next_base58()
    print("Snowflake int:", s1)
    print("Snowflake b58:", s2)

    print("Prefixed:", with_prefix("order", u1))
