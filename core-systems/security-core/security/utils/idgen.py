# file: security-core/security/utils/idgen.py
from __future__ import annotations

import os
import time
import uuid
import socket
import struct
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Tuple, Literal, Union

# ======================================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ/КОДИРОВКИ
# ======================================================================================

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # без I,L,O,U
_CROCKFORD_MAP = {c: i for i, c in enumerate(_CROCKFORD)}
_BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_BASE62_MAP = {c: i for i, c in enumerate(_BASE62)}

def _b32_crockford_encode(b: bytes) -> str:
    """Без заполнителей, 5 бит на символ. Для ULID длина 26."""
    bits = 0
    acc = 0
    out = []
    for byte in b:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(_CROCKFORD[(acc >> bits) & 0x1F])
    if bits:
        out.append(_CROCKFORD[(acc << (5 - bits)) & 0x1F])
    return "".join(out)

def _b32_crockford_decode(s: str) -> bytes:
    acc = 0
    bits = 0
    out = bytearray()
    for ch in s.upper():
        if ch in "-_":
            continue
        v = _CROCKFORD_MAP.get(ch)
        if v is None:
            raise ValueError("invalid Crockford base32 char")
        acc = (acc << 5) | v
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    return bytes(out)

def _b62_encode_int(n: int) -> str:
    if n == 0:
        return "0"
    out = []
    neg = n < 0
    n = -n if neg else n
    while n:
        n, r = divmod(n, 62)
        out.append(_BASE62[r])
    if neg:
        out.append("-")
    return "".join(reversed(out))

def _b62_decode_int(s: str) -> int:
    neg = s.startswith("-")
    if neg:
        s = s[1:]
    acc = 0
    for ch in s:
        v = _BASE62_MAP.get(ch)
        if v is None:
            raise ValueError("invalid base62 char")
        acc = acc * 62 + v
    return -acc if neg else acc

def _now_ms() -> int:
    return int(time.time()*1000)

def _iso(dt_ms: int) -> str:
    return datetime.fromtimestamp(dt_ms/1000, tz=timezone.utc).isoformat().replace("+00:00","Z")

# ======================================================================================
# ULID (RFC-like: 48b time ms, 80b randomness). Монотонный вариант для одной процесс/машины.
# ======================================================================================

class _UlidState:
    __slots__ = ("lock", "last_ms", "rand80")
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.last_ms = -1
        self.rand80 = 0

_ulid_state = _UlidState()

def ulid_new() -> str:
    """Генерация ULID (не гарантирует монотонность внутри одного ms). 26 символов Crockford Base32."""
    t = _now_ms() & ((1<<48)-1)
    rand = secrets.token_bytes(10)
    b = t.to_bytes(6, "big") + rand
    return _b32_crockford_encode(b)[:26]

def ulid_new_monotonic() -> str:
    """Монотонный ULID: при равном миллисекундном таймштампе увеличивает 80‑битный счётчик."""
    t = _now_ms() & ((1<<48)-1)
    with _ulid_state.lock:
        if t > _ulid_state.last_ms:
            _ulid_state.last_ms = t
            _ulid_state.rand80 = int.from_bytes(secrets.token_bytes(10), "big")
        else:
            _ulid_state.rand80 = (_ulid_state.rand80 + 1) & ((1<<80)-1)
            if _ulid_state.rand80 == 0:
                # переполнение в том же ms — дождаться следующей ms
                while True:
                    t2 = _now_ms() & ((1<<48)-1)
                    if t2 != t:
                        t = t2
                        _ulid_state.last_ms = t
                        _ulid_state.rand80 = int.from_bytes(secrets.token_bytes(10), "big")
                        break
        b = t.to_bytes(6, "big") + _ulid_state.rand80.to_bytes(10, "big")
    return _b32_crockford_encode(b)[:26]

def ulid_parse(s: str) -> Tuple[int, bytes]:
    """Возвращает (epoch_ms, randomness_10bytes)."""
    raw = _b32_crockford_decode(s)
    if len(raw) < 16:
        raise ValueError("invalid ULID length")
    return (int.from_bytes(raw[:6],"big"), raw[6:16])

# ======================================================================================
# KSUID (timestamp seconds since 2014‑05‑13 00:00:00Z + 16B randomness). Base62 длина 27.
# ======================================================================================

_KSUID_EPOCH = 1400000000  # фиксированная эпоха KSUID (секунды)
def ksuid_new() -> str:
    ts = int(time.time()) - _KSUID_EPOCH
    if ts < 0:
        ts = 0
    body = struct.pack(">I", ts) + secrets.token_bytes(16)
    n = int.from_bytes(body, "big")
    s = _b62_encode_int(n)
    # KSUID стандартно 27 символов; добиваем ведущими нулями base62 при необходимости
    return s.rjust(27, "0")

def ksuid_parse(s: str) -> Tuple[int, bytes]:
    """Возвращает (epoch_ms приблизительно, randomness_16bytes)."""
    n = _b62_decode_int(s)
    b = n.to_bytes(20, "big")
    ts = struct.unpack(">I", b[:4])[0] + _KSUID_EPOCH
    return ts*1000, b[4:]

# ======================================================================================
# Snowflake‑совместимые 64‑битные ID: [41b time_ms_since_epoch | 10b worker | 12b seq]
# ======================================================================================

@dataclass
class SnowflakeConfig:
    epoch_ms: int = int(datetime(2020,1,1,tzinfo=timezone.utc).timestamp()*1000)
    worker_id_bits: int = 10
    sequence_bits: int = 12
    allow_clock_rollback_ms: int = 0  # 0 = ждать; >0 = допуск, меньше — усечём

class Snowflake:
    def __init__(self, cfg: Optional[SnowflakeConfig]=None, worker_id: Optional[int]=None) -> None:
        self.cfg = cfg or SnowflakeConfig()
        self.max_worker = (1<<self.cfg.worker_id_bits)-1
        self.max_seq = (1<<self.cfg.sequence_bits)-1
        self.worker_id = self._resolve_worker(worker_id) & self.max_worker
        self.lock = threading.Lock()
        self.last_ms = -1
        self.seq = 0

    def _resolve_worker(self, wid: Optional[int]) -> int:
        if wid is not None:
            return wid
        # ENV приоритетно
        env = os.getenv("SC_IDGEN_NODE_ID")
        if env and env.isdigit():
            return int(env)
        # Фоллбек: хеш host+pid в диапазон
        h = hash(f"{socket.gethostname()}:{os.getpid()}")
        return h & 0x7FFFFFFF

    def _timestamp(self) -> int:
        return _now_ms()

    def next_int(self) -> int:
        with self.lock:
            now = self._timestamp()
            if now < self.last_ms:
                # откат часов
                delta = self.last_ms - now
                if delta <= self.cfg.allow_clock_rollback_ms:
                    now = self.last_ms  # усечём в прошлый known‑good
                else:
                    # ждём до last_ms
                    wait_ms = delta
                    end = time.time() + wait_ms/1000.0
                    while _now_ms() < self.last_ms and time.time() < end:
                        time.sleep(0.0005)
                    now = max(_now_ms(), self.last_ms)
            if now == self.last_ms:
                self.seq = (self.seq + 1) & self.max_seq
                if self.seq == 0:
                    # исчерпана квота на ms — ждём следующую миллисекунду
                    while True:
                        now = self._timestamp()
                        if now > self.last_ms:
                            break
                        time.sleep(0.0002)
            else:
                self.seq = secrets.randbelow(3)  # минимальное рандомизирование стартовой последовательности
            self.last_ms = now

            t = (now - self.cfg.epoch_ms)
            if t < 0:
                t = 0
            if t >= (1<<41):
                raise OverflowError("timestamp overflow for snowflake epoch")

            return (t << (self.cfg.worker_id_bits + self.cfg.sequence_bits)) | (self.worker_id << self.cfg.sequence_bits) | self.seq

    def next_str(self) -> str:
        return _b62_encode_int(self.next_int())

    @staticmethod
    def decode(n: int, cfg: Optional[SnowflakeConfig]=None) -> Tuple[int,int,int]:
        cfg = cfg or SnowflakeConfig()
        seq_mask = (1<<cfg.sequence_bits)-1
        wid_mask = (1<<cfg.worker_id_bits)-1
        seq = n & seq_mask
        wid = (n >> cfg.sequence_bits) & wid_mask
        t = n >> (cfg.worker_id_bits + cfg.sequence_bits)
        ts_ms = t + cfg.epoch_ms
        return ts_ms, wid, seq

# ======================================================================================
# UUIDv4 (fallback, не time‑sortable)
# ======================================================================================

def uuid4_str() -> str:
    return str(uuid.uuid4())

# ======================================================================================
# ФАСАД ГЕНЕРАТОРА
# ======================================================================================

IdStrategy = Literal["ulid", "ulid-mono", "ksuid", "snowflake-int", "snowflake", "uuid4"]

@dataclass
class IdGeneratorConfig:
    default_strategy: IdStrategy = "ulid-mono"
    snowflake: SnowflakeConfig = SnowflakeConfig()

class IdGenerator:
    """
    Унифицированный генератор ID для security-core.
    Стратегии:
      - ulid        : 26‑символьный Crockford Base32
      - ulid-mono   : монотонный ULID (26 символов)
      - ksuid       : 27‑символьный Base62
      - snowflake   : 64‑битный int → Base62 строка
      - snowflake-int: 64‑битный int (целое)
      - uuid4       : стандартный UUIDv4, 36 символов
    """
    def __init__(self, cfg: Optional[IdGeneratorConfig]=None, worker_id: Optional[int]=None) -> None:
        self.cfg = cfg or IdGeneratorConfig()
        self._sf = Snowflake(self.cfg.snowflake, worker_id=worker_id)

    def new(self, strategy: Optional[IdStrategy]=None) -> Union[str, int]:
        st = strategy or self.cfg.default_strategy
        if st == "ulid":
            return ulid_new()
        if st == "ulid-mono":
            return ulid_new_monotonic()
        if st == "ksuid":
            return ksuid_new()
        if st == "snowflake":
            return self._sf.next_str()
        if st == "snowflake-int":
            return self._sf.next_int()
        if st == "uuid4":
            return uuid4_str()
        raise ValueError("unknown id strategy")

# ======================================================================================
# ДЕКОДЕРЫ/МЕТАДАННЫЕ ВРЕМЕНИ
# ======================================================================================

def extract_timestamp(id_value: Union[str, int]) -> Optional[int]:
    """
    Пытается извлечь UNIX epoch миллисекунды из известных форматов (ULID/KSUID/Snowflake).
    Возвращает epoch_ms или None, если не распознано.
    """
    try:
        if isinstance(id_value, int):
            ts, _, _ = Snowflake.decode(id_value)
            return ts
        s = str(id_value)
        if len(s) == 26 and s.isalnum():
            ts, _ = ulid_parse(s)
            return ts
        if len(s) == 27:
            ts, _ = ksuid_parse(s)
            return ts
        # возможно, Base62 Snowflake
        if 8 <= len(s) <= 13:  # типичные размеры base62 для 64‑бит
            n = _b62_decode_int(s)
            ts, _, _ = Snowflake.decode(n)
            return ts
    except Exception:
        return None
    return None

# ======================================================================================
# САМОПРОВЕРКА/ПРИМЕРЫ
# ======================================================================================

def _selftest() -> None:
    gen = IdGenerator()
    a = [gen.new("ulid-mono") for _ in range(5)]
    b = [gen.new("ulid") for _ in range(5)]
    c = [gen.new("ksuid") for _ in range(3)]
    sf = IdGenerator(IdGeneratorConfig(default_strategy="snowflake")).new("snowflake")
    sfi = IdGenerator(IdGeneratorConfig(default_strategy="snowflake-int")).new("snowflake-int")
    uu = uuid4_str()

    assert len(a[0]) == 26
    assert len(b[0]) == 26
    assert len(c[0]) == 27
    assert isinstance(sfi, int)
    # проверим сортировку ULID‑moно: лексикографическая близка к временному
    assert a == sorted(a)
    # извлечение времени
    for x in a + c + [sf, sfi]:
        ts = extract_timestamp(x)
        assert ts is not None and ts > 1577836800000  # после 2020-01-01

    print("ULID(mono):", a[0])
    print("ULID:", b[0])
    print("KSUID:", c[0])
    print("Snowflake(base62):", sf)
    print("Snowflake(int):", sfi)
    print("UUIDv4:", uu)
    print("OK")

if __name__ == "__main__":
    _selftest()
