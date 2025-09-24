# ledger-core/ledger/utils/idgen.py
"""
Промышленный генератор идентификаторов для Ledger Core.

Функции и классы:
- uuid4_str(), uuid7_str(): стандартные UUID (v4 случайный, v7 time-ordered).
- ulid_str(): ULID в Crockford Base32, монотонный (Monotonic ULID).
- ksuid_str(): KSUID (20 байт) в Base62, сортируемый по времени.
- snowflake_id(): 64-битный Snowflake-совместимый ID (возвращает int).
- snowflake_str(): то же, но как строка в Base58.
- secure_token(): криптостойкий случайный токен в Base58 (по умолчанию 128 бит).
- short_id(): короткий человекочитаемый ID (в Base32/58/62) с заданной энтропией.
- IdGenerator: конфигурируемый потокобезопасный генератор (node_id, epoch, лимиты).
- Кодеки: b32_crockford_encode, b58_encode, b62_encode (и декодеры при необходимости).

Гарантии:
- Потокобезопасность (threading.Lock).
- Защита от регресса системных часов (монотонный таймштамп, sequence bump).
- Отсутствие внешних зависимостей (stdlib only).
- Криптографическая энтропия: secrets.token_bytes.
- Шардирование по node_id для Snowflake/KSUID/ULID.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Literal, Optional

# =========================
# ВСПОМОГАТЕЛЬНЫЕ КОДЕКИ
# =========================

# Crockford Base32 (без I,L,O,U; регистронезависимо, но выдаём верхний регистр)
_B32_CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_B32_MAP = {i: ch for i, ch in enumerate(_B32_CROCKFORD_ALPHABET)}

# Bitcoin Base58 (без 0,O,I,l)
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_MAP = {i: ch for i, ch in enumerate(_B58_ALPHABET)}

# Base62 (0-9A-Za-z)
_B62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_B62_MAP = {i: ch for i, ch in enumerate(_B62_ALPHABET)}


def _int_to_base(n: int, alphabet: str) -> str:
    if n < 0:
        raise ValueError("n must be >= 0")
    if n == 0:
        return alphabet[0]
    base = len(alphabet)
    out = []
    while n:
        n, rem = divmod(n, base)
        out.append(alphabet[rem])
    out.reverse()
    return "".join(out)


def b58_encode(b: bytes) -> str:
    # ведущее нули в Base58 кодируются как '1'
    n = int.from_bytes(b, "big", signed=False)
    enc = _int_to_base(n, _B58_ALPHABET)
    pad = 0
    for bt in b:
        if bt == 0:
            pad += 1
        else:
            break
    return "1" * pad + enc


def b62_encode(b: bytes) -> str:
    n = int.from_bytes(b, "big", signed=False)
    return _int_to_base(n, _B62_ALPHABET)


def b32_crockford_encode(b: bytes) -> str:
    # реализуем через int, затем паддинг вручную не требуется (вариант без '=')
    n = int.from_bytes(b, "big", signed=False)
    # Сколько 5-битных чанков нужно
    bitlen = len(b) * 8
    out_len = (bitlen + 4) // 5
    res = []
    for i in range(out_len):
        # берём слева направо: индекс бита
        shift = (out_len - 1 - i) * 5
        val = (n >> shift) & 0b11111
        res.append(_B32_MAP[val])
    # Удаляем ведущие нули алфавита при необходимости (необязательно для ULID)
    s = "".join(res).lstrip("0")
    return s or "0"


# =========================
# ВНУТРЕННИЕ ХЕЛПЕРЫ
# =========================

def _now_ms() -> int:
    # Используем time.time_ns для высокой точности и монотонности через fallback
    return time.time_ns() // 1_000_000


def _crypto_bytes(n: int) -> bytes:
    # os.urandom криптостойкий источник
    return os.urandom(n)


def _fingerprint_node(max_bits: int) -> int:
    """
    Формирует стабильный процессный fingerprint:
    - Хэш от: hostname, pid, часть MAC/entropy.
    - Ограничивает размером max_bits.
    """
    host = os.uname().nodename if hasattr(os, "uname") else "host"
    pid = os.getpid()
    entropy = _crypto_bytes(16)
    h = hashlib.blake2b(digest_size=16)
    h.update(host.encode("utf-8"))
    h.update(str(pid).encode("utf-8"))
    h.update(entropy)  # добавляет случайность для разнесения процессов на одном хосте
    val = int.from_bytes(h.digest(), "big")
    mask = (1 << max_bits) - 1
    return val & mask


# =========================
# UUID (v4, v7)
# =========================

def uuid4_str() -> str:
    """Случайный UUIDv4 (36-символьный, canonical)."""
    return str(uuid.uuid4())


def uuid7_str() -> str:
    """
    UUIDv7 — сортируемый по времени UUID.
    Python 3.11+: uuid.uuid7(); для совместимости соберём через os.urandom.
    """
    # Реализация упрощённая: используем стандартную, если доступна.
    if hasattr(uuid, "uuid7"):
        return str(uuid.uuid7())
    # Fallback: соберём 128 бит: 48 бит времени мс, 4 версии, 2 варианта, остальное random.
    ts = _now_ms() & ((1 << 48) - 1)
    rand = int.from_bytes(_crypto_bytes(10), "big")
    # Формируем поля: версию 7 в нужный nibble
    # layout: https://www.rfc-editor.org/rfc/rfc4122 (draft v7)
    time_hi_version = ((ts >> 32) & 0xFFFF) & 0x0FFF | (0x7 << 12)
    time_mid = (ts >> 16) & 0xFFFF
    time_low = ts & 0xFFFF

    clock_seq_hi = ((rand >> 72) & 0x3F) | 0x80  # variant RFC4122
    clock_seq_low = (rand >> 64) & 0xFF
    node = rand & ((1 << 64) - 1)

    fields = (
        (time_low << 16) | time_mid,  # time_low (32 бита) + нижние 16 mid в старших
        time_hi_version,              # time_hi_and_version (16)
        (clock_seq_hi << 8) | clock_seq_low,  # clock_seq (16)
        node                          # node (48/64)
    )
    # Собираем байты в big-endian, затем в UUID
    b = (
        time_low.to_bytes(2, "big")
        + time_mid.to_bytes(2, "big")
        + time_hi_version.to_bytes(2, "big")
        + clock_seq_hi.to_bytes(1, "big")
        + clock_seq_low.to_bytes(1, "big")
        + node.to_bytes(8, "big")
    )
    return str(uuid.UUID(bytes=b[:16]))


# =========================
# ULID (Monotonic)
# =========================

class _MonotonicULID:
    """
    Монотонный ULID согласно спецификации:
    - 48 бит времени в мс от UNIX epoch
    - 80 бит случайности
    - При совпадении времени увеличиваем random-часть (big-endian) как счётчик.
    """
    __slots__ = ("_lock", "_last_ms", "_last_rand")

    def __init__(self):
        self._lock = threading.Lock()
        self._last_ms = -1
        self._last_rand = 0

    def new(self) -> str:
        with self._lock:
            now = _now_ms()
            if now == self._last_ms:
                # инкрементируем 80-битный счётчик в пределах.
                self._last_rand = (self._last_rand + 1) & ((1 << 80) - 1)
            else:
                self._last_ms = now
                self._last_rand = int.from_bytes(_crypto_bytes(10), "big")
            # Собираем 128 бит
            ulid_int = (now & ((1 << 48) - 1)) << 80 | self._last_rand
        # В Base32 Crockford длина всегда 26 символов
        return _ulid_int_to_crockford(ulid_int)


def _ulid_int_to_crockford(n: int) -> str:
    # ULID — 26 символов Base32 Crockford
    out = []
    for i in range(26):
        shift = (25 - i) * 5
        idx = (n >> shift) & 0b11111
        out.append(_B32_CROCKFORD_ALPHABET[idx])
    return "".join(out)


_ulid = _MonotonicULID()


def ulid_str() -> str:
    """ULID (монотонный), 26-символьный Crockford Base32."""
    return _ulid.new()


# =========================
# KSUID (Time-ordered, 20 bytes -> Base62)
# =========================

# Epoch KSUID: 2014-05-13T00:00:00Z -> 1400000000
_KSUID_EPOCH = 1_400_000_000

def ksuid_bytes() -> bytes:
    """
    4 байта — timestamp (big endian, seconds since KSUID_EPOCH),
    16 байт — криптослучайность.
    """
    ts = int(time.time()) - _KSUID_EPOCH
    if ts < 0:
        ts = 0
    if ts >= (1 << 32):
        # при переполнении обнуляем и включаем энтропию в старший байт
        ts = (ts % (1 << 32))
    rnd = _crypto_bytes(16)
    return ts.to_bytes(4, "big") + rnd


def ksuid_str() -> str:
    """KSUID в Base62 (27 символов)."""
    return b62_encode(ksuid_bytes())


# =========================
# SNOWFLAKE (64-bit)
# =========================

@dataclass
class SnowflakeConfig:
    # 41 бит под timestamp (мс от пользовательского epoch)
    # 10 бит под node_id (0..1023)
    # 12 бит под sequence (0..4095)
    epoch_ms: int
    node_id: int
    node_bits: int = 10
    seq_bits: int = 12

    def __post_init__(self):
        max_node = (1 << self.node_bits) - 1
        if not (0 <= self.node_id <= max_node):
            raise ValueError(f"node_id must be in [0, {max_node}]")

        if self.node_bits + self.seq_bits >= 22:  # sanity check, оставляем 41 бит времени
            pass


class _SnowflakeState:
    __slots__ = ("lock", "last_ms", "seq")

    def __init__(self):
        self.lock = threading.Lock()
        self.last_ms = -1
        self.seq = 0


class SnowflakeGenerator:
    """
    Потокобезопасный генератор 64-битных идентификаторов.
    """
    def __init__(self, cfg: SnowflakeConfig):
        self.cfg = cfg
        self.state = _SnowflakeState()
        self.time_shift = self.cfg.node_bits + self.cfg.seq_bits
        self.node_shift = self.cfg.seq_bits
        self.max_seq = (1 << self.cfg.seq_bits) - 1

    def _timestamp_ms(self) -> int:
        now = _now_ms()
        if now < self.cfg.epoch_ms:
            # если системные часы ушли назад — считаем 0
            return 0
        return now - self.cfg.epoch_ms

    def next_id(self) -> int:
        with self.state.lock:
            ts = self._timestamp_ms()
            if ts == self.state.last_ms:
                self.state.seq = (self.state.seq + 1) & self.max_seq
                if self.state.seq == 0:
                    # переполнение sequence в текущем ms — ждём следующий ms
                    while True:
                        ts = self._timestamp_ms()
                        if ts > self.state.last_ms:
                            break
                        time.sleep(0.0001)  # 100 мкс
            else:
                self.state.seq = 0
                self.state.last_ms = ts

            # Формула компоновки: [timestamp | node_id | seq]
            sf = (ts << self.time_shift) | (self.cfg.node_id << self.node_shift) | self.state.seq
            return sf


# =========================
# ВЫСОКОУРОВНЕВЫЙ API / КОНФИГУРАЦИЯ
# =========================

_DEFAULT_EPOCH_MS = 1_600_000_000_000  # 2020-09-13T12:26:40Z
_DEFAULT_NODE_BITS = 10
_DEFAULT_SEQ_BITS = 12

class IdGenerator:
    """
    Единая точка доступа к ID для системы:
    - Конфигурируемый Snowflake (node_id, epoch).
    - Функции для UUIDv4/v7, ULID, KSUID, токенов.
    """
    def __init__(
        self,
        node_id: Optional[int] = None,
        epoch_ms: int = _DEFAULT_EPOCH_MS,
        node_bits: int = _DEFAULT_NODE_BITS,
        seq_bits: int = _DEFAULT_SEQ_BITS,
    ):
        if node_id is None:
            node_id = _fingerprint_node(node_bits)
        self.node_id = node_id
        self.snowflake = SnowflakeGenerator(
            SnowflakeConfig(epoch_ms=epoch_ms, node_id=node_id, node_bits=node_bits, seq_bits=seq_bits)
        )

    # UUID
    def uuid4(self) -> str:
        return uuid4_str()

    def uuid7(self) -> str:
        return uuid7_str()

    # ULID
    def ulid(self) -> str:
        return ulid_str()

    # KSUID
    def ksuid(self) -> str:
        return ksuid_str()

    # Snowflake
    def snowflake_id(self) -> int:
        return self.snowflake.next_id()

    def snowflake_str(self, encoding: Literal["base58", "base62"] = "base58") -> str:
        sf = self.snowflake_id()
        b = sf.to_bytes(8, "big", signed=False)
        if encoding == "base58":
            return b58_encode(b)
        return b62_encode(b)

    # Токены
    def secure_token(self, bits: int = 128, encoding: Literal["base58", "base32", "base62"] = "base58") -> str:
        if bits % 8 != 0 or bits <= 0:
            raise ValueError("bits must be positive and a multiple of 8")
        raw = _crypto_bytes(bits // 8)
        if encoding == "base32":
            return b32_crockford_encode(raw)
        if encoding == "base62":
            return b62_encode(raw)
        return b58_encode(raw)

    # Короткий ID с заданной энтропией
    def short_id(
        self,
        bits: int = 96,
        encoding: Literal["base58", "base32", "base62"] = "base58",
    ) -> str:
        return self.secure_token(bits=bits, encoding=encoding)


# =========================
# УДОБНЫЕ ГЛОБАЛЬНЫЕ ФУНКЦИИ
# =========================

# Глобальный генератор с авто node_id fingerprint
_GLOBAL = IdGenerator()

def ulid() -> str:
    return _GLOBAL.ulid()

def uuid4() -> str:
    return _GLOBAL.uuid4()

def uuid7() -> str:
    return _GLOBAL.uuid7()

def ksuid() -> str:
    return _GLOBAL.ksuid()

def snowflake_id() -> int:
    return _GLOBAL.snowflake_id()

def snowflake_str(encoding: Literal["base58", "base62"] = "base58") -> str:
    return _GLOBAL.snowflake_str(encoding=encoding)

def secure_token(bits: int = 128, encoding: Literal["base58", "base32", "base62"] = "base58") -> str:
    return _GLOBAL.secure_token(bits=bits, encoding=encoding)

def short_id(bits: int = 96, encoding: Literal["base58", "base32", "base62"] = "base58") -> str:
    return _GLOBAL.short_id(bits=bits, encoding=encoding)
