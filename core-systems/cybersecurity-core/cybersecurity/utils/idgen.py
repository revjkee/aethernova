# cybersecurity-core/cybersecurity/utils/idgen.py
from __future__ import annotations

import os
import time
import uuid as _uuid
import secrets
import threading
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple, Iterable

# =============================================================================
# Константы и алфавиты
# =============================================================================

# Base32 Crockford (без I, L, O, U), верхний регистр по ULID-спецификации
_B32_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
# Base58 (Bitcoin)
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
# Base62 (KSUID)
_B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

# Эпоха KSUID: 2014-05-13T00:00:00Z
_KSUID_EPOCH = int(datetime(2014, 5, 13, tzinfo=timezone.utc).timestamp())

# Эпоха для Snowflake-подобных ID (настраиваемая, по умолчанию 2020-01-01)
_SNOWFLAKE_EPOCH = int(datetime(2020, 1, 1, tzinfo=timezone.utc).timestamp() * 1000)

# =============================================================================
# Служебные функции времени и случайности
# =============================================================================

def _utc_now_ms() -> int:
    return int(time.time() * 1000)

def _utc_now_s() -> int:
    return int(time.time())

def _os_urandom(n: int) -> bytes:
    return os.urandom(n)

def _machine_fingerprint(n: int = 2) -> bytes:
    """
    Стабильный локальный отпечаток машины для распределенной уникальности.
    Не раскрывает MAC/hostname напрямую: хэшируем и усекaем.
    """
    try:
        # /etc/machine-id (Linux) или HOSTNAME
        src = None
        mid_paths = ("/etc/machine-id", "/var/lib/dbus/machine-id")
        for p in mid_paths:
            if os.path.exists(p):
                with open(p, "rb") as fh:
                    src = fh.read().strip()
                    break
        if src is None:
            src = (os.uname().nodename if hasattr(os, "uname") else os.getenv("HOSTNAME","unknown")).encode("utf-8")
    except Exception:
        src = _uuid.getnode().to_bytes(6, "big", signed=False)
    h = hashlib.blake2b(src, digest_size=n)
    return h.digest()

# =============================================================================
# Кодеки: Base32 Crockford, Base58, Base62
# =============================================================================

def b32_crockford_encode(data: bytes) -> str:
    """
    Без паддинга, верхний регистр, совместимо с ULID.
    """
    bits = 0
    value = 0
    out = []
    for b in data:
        value = (value << 8) | b
        bits += 8
        while bits >= 5:
            idx = (value >> (bits - 5)) & 0x1F
            out.append(_B32_CROCKFORD[idx])
            bits -= 5
    if bits:
        out.append(_B32_CROCKFORD[(value << (5 - bits)) & 0x1F])
    return "".join(out)

def b32_crockford_decode(s: str) -> bytes:
    """
    Терпимо к регистрам и заменам O->0, I/L->1.
    """
    s = s.strip().upper().replace("-", "")
    s = s.replace("O", "0").replace("I", "1").replace("L", "1")
    rev = {ch: i for i, ch in enumerate(_B32_CROCKFORD)}
    bits = 0
    value = 0
    out = bytearray()
    for ch in s:
        if ch not in rev:
            raise ValueError("invalid Base32 Crockford character")
        value = (value << 5) | rev[ch]
        bits += 5
        if bits >= 8:
            out.append((value >> (bits - 8)) & 0xFF)
            bits -= 8
    return bytes(out)

def base58_encode(data: bytes) -> str:
    # ведущее нулевые байты -> '1'
    n = int.from_bytes(data, "big")
    out = []
    while n > 0:
        n, rem = divmod(n, 58)
        out.append(_B58[rem])
    # ведущие нули
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return "1" * pad + "".join(reversed(out or ["1"]))

def base62_encode(data: bytes, *, min_len: int = 0) -> str:
    n = int.from_bytes(data, "big")
    out = []
    while n > 0:
        n, rem = divmod(n, 62)
        out.append(_B62[rem])
    s = "".join(reversed(out or ["0"]))
    if min_len and len(s) < min_len:
        s = _B62[0] * (min_len - len(s)) + s
    return s

# =============================================================================
# ULID с монотонике (RFC 4122 совместим в 128 битах, 26 Base32 символов)
# =============================================================================

class _ULIDState:
    __slots__ = ("lock", "last_ms", "last_rand")

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.last_ms: int = -1
        self.last_rand: bytearray = bytearray(10)

_ULID_STATE = _ULIDState()

def ulid_bytes() -> bytes:
    """
    Генерирует ULID 16 байт: 48 бит timestamp (мс) + 80 бит случайности.
    Гарантирует монотонике в рамках процесса/потока.
    """
    ts_ms = _utc_now_ms()
    with _ULID_STATE.lock:
        if ts_ms > _ULID_STATE.last_ms:
            _ULID_STATE.last_ms = ts_ms
            _ULID_STATE.last_rand = bytearray(_os_urandom(10))
        else:
            # монотонике: инкрементируем 80-битную случайную часть
            i = 9
            while i >= 0:
                if _ULID_STATE.last_rand[i] != 0xFF:
                    _ULID_STATE.last_rand[i] += 1
                    break
                _ULID_STATE.last_rand[i] = 0
                i -= 1
            if i < 0:
                # переполнение — ждём следующий миллисекундный тик
                while ts_ms <= _ULID_STATE.last_ms:
                    time.sleep(0.001)
                    ts_ms = _utc_now_ms()
                _ULID_STATE.last_ms = ts_ms
                _ULID_STATE.last_rand = bytearray(_os_urandom(10))
        ts = ts_ms.to_bytes(6, "big")
        return ts + bytes(_ULID_STATE.last_rand)

def ulid() -> str:
    """
    26-символьная Base32 Crockford строка (верхний регистр), лексикографически сортируемая по времени.
    """
    raw = ulid_bytes()
    # точная 26-символьная ULID-печать (10 для времени, 16 для случайности)
    time_part = b32_crockford_encode(raw[:6])
    rand_part = b32_crockford_encode(raw[6:])
    # При обычном кодировании длины получаются 10 и 16 символов соответственно
    return (time_part[:10] + rand_part[:16]).upper()

def parse_ulid(s: str) -> Tuple[int, bytes]:
    """
    Возвращает (timestamp_ms, random_80bit).
    Принимает 26-символьную строку ULID.
    """
    s = s.strip()
    if len(s) != 26:
        raise ValueError("ULID must be 26 chars")
    # Декодируем по частям
    ts_bytes = b32_crockford_decode(s[:10])
    rnd_bytes = b32_crockford_decode(s[10:])
    # Из-за 5-битного выравнивания декод возвращает 8/?? байт; берем нужные 6 и 10
    ts = int.from_bytes(ts_bytes[-6:], "big")
    rnd = (rnd_bytes if len(rnd_bytes) == 10 else rnd_bytes[-10:])
    if len(rnd) != 10:
        raise ValueError("invalid ULID random part")
    return ts, rnd

def ulid_to_uuid(s: str) -> _uuid.UUID:
    ts, rnd = parse_ulid(s)
    return _uuid.UUID(bytes=ts.to_bytes(6, "big") + rnd)

# =============================================================================
# UUID v4 (случайный) и UUID v7 (time-ordered, draft/RFC 9562)
# =============================================================================

def uuid4() -> _uuid.UUID:
    return _uuid.uuid4()

def uuid7() -> _uuid.UUID:
    """
    UUIDv7: 48 бит Unix миллисекунд, затем 4 бита версии, 12 бит rand_a,
    2 бита варианта и 62 бита rand_b (итого 128 бит).
    """
    unix_ms = _utc_now_ms()
    ts = unix_ms.to_bytes(6, "big")
    rand_a = secrets.randbits(12)
    rand_b = secrets.randbits(62)

    b = bytearray(16)
    b[0:6] = ts
    b[6] = (0x70 | ((rand_a >> 8) & 0x0F))           # версия 7 + старшие 4 бита rand_a
    b[7] = rand_a & 0xFF                             # младшие 8 бита rand_a
    top6 = (rand_b >> 56) & 0x3F                     # старшие 6 бит rand_b
    rest = rand_b & ((1 << 56) - 1)                  # оставшиеся 56 бит
    b[8] = 0x80 | top6                               # вариант RFC 4122 '10'
    rest_bytes = rest.to_bytes(7, "big")
    b[9:16] = rest_bytes
    return _uuid.UUID(bytes=bytes(b))

# =============================================================================
# KSUID (20 байт -> 27 Base62 символов)
# =============================================================================

@dataclass(frozen=True)
class KSUID:
    ts: int           # секунды с KSUID-эпохи
    payload: bytes    # 16 байт случайности

    @property
    def bytes(self) -> bytes:
        return self.ts.to_bytes(4, "big") + self.payload

    def __str__(self) -> str:
        return base62_encode(self.bytes, min_len=27)

def ksuid(now_s: Optional[int] = None) -> KSUID:
    ts = (now_s if now_s is not None else _utc_now_s()) - _KSUID_EPOCH
    if ts < 0 or ts >= 2**32:
        raise OverflowError("KSUID timestamp out of range")
    return KSUID(ts=ts, payload=_os_urandom(16))

def ksuid_from_str(s: str) -> KSUID:
    # Декодирование base62 обратно в 20 байт
    n = 0
    for ch in s.strip():
        i = _B62.find(ch)
        if i < 0:
            raise ValueError("invalid base62 character in KSUID")
        n = n * 62 + i
    raw = n.to_bytes(20, "big")
    ts = int.from_bytes(raw[:4], "big")
    return KSUID(ts=ts, payload=raw[4:])

def ksuid_datetime(k: KSUID) -> datetime:
    return datetime.fromtimestamp(k.ts + _KSUID_EPOCH, tz=timezone.utc)

# =============================================================================
# Короткие ID (URL-safe) без статистического смещения (а-ля nanoid)
# =============================================================================

_DEFAULT_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz-"

def _random_indices(n: int, alphabet_len: int) -> Iterable[int]:
    """
    Генерация индексов без модуло-смещения.
    Берём блобы из os.urandom и используем только байты < step*alphabet_len.
    """
    step = (256 // alphabet_len) * alphabet_len
    buf = bytearray()
    while len(buf) < n:
        chunk = bytearray(_os_urandom(n))
        for b in chunk:
            if b < step:
                buf.append(b % alphabet_len)
                if len(buf) == n:
                    break
    return buf

def short_id(length: int = 21, alphabet: str = _DEFAULT_ALPHABET, prefix: str = "") -> str:
    if length <= 0:
        raise ValueError("length must be > 0")
    if not (2 <= len(alphabet) <= 255):
        raise ValueError("alphabet size must be in [2..255]")
    idxs = _random_indices(length, len(alphabet))
    s = "".join(alphabet[i] for i in idxs)
    return (prefix + s) if prefix else s

def short_id_with_fingerprint(length: int = 21, alphabet: str = _DEFAULT_ALPHABET, fp_len_bytes: int = 2) -> str:
    """
    Встраивает машинный отпечаток (по умолчанию 2 байта -> 3 base62 символа) в начало строки.
    """
    fp = _machine_fingerprint(fp_len_bytes)
    fp_b62 = base62_encode(fp, min_len=max(1, (fp_len_bytes * 8 + 5) // 6))
    core = short_id(length=length, alphabet=alphabet)
    return fp_b62 + core

# =============================================================================
# Snowflake-подобный 64-битный ID: 41b time | 10b worker | 13b seq
# =============================================================================

class Snowflake:
    """
    Потокобезопасный генератор 64-битных, возрастающих в рамках воркера ID.
    """
    __slots__ = ("epoch_ms", "worker_id", "lock", "last_ms", "seq")

    def __init__(self, worker_id: int, *, epoch_ms: int = _SNOWFLAKE_EPOCH) -> None:
        if not (0 <= worker_id < 2**10):
            raise ValueError("worker_id must be in [0..1023]")
        self.epoch_ms = epoch_ms
        self.worker_id = worker_id
        self.lock = threading.Lock()
        self.last_ms = -1
        self.seq = 0

    def _now_ms(self) -> int:
        return _utc_now_ms()

    def next_id(self) -> int:
        with self.lock:
            now = self._now_ms()
            if now < self.last_ms:
                # Системное время откатилось — ждём до последнего значения
                wait = self.last_ms - now
                time.sleep(wait / 1000.0)
                now = self._now_ms()
            if now == self.last_ms:
                self.seq = (self.seq + 1) & ((1 << 13) - 1)
                if self.seq == 0:
                    # переполнение последовательности — ждём следующий миллисекундный тик
                    while now <= self.last_ms:
                        time.sleep(0.001)
                        now = self._now_ms()
            else:
                self.seq = 0
            self.last_ms = now
            t = (now - self.epoch_ms) & ((1 << 41) - 1)
            return (t << (10 + 13)) | (self.worker_id << 13) | self.seq

def snowflake_default() -> Snowflake:
    # worker_id из машинного отпечатка (10 бит)
    fp = int.from_bytes(_machine_fingerprint(2), "big") & 0x3FF
    return Snowflake(worker_id=fp)

# =============================================================================
# Единый фасад
# =============================================================================

class IdGen:
    """
    Унифицированный генератор ID для приложения.
    """
    def __init__(self, *, snowflake: Optional[Snowflake] = None) -> None:
        self.snowflake = snowflake or snowflake_default()

    # ULID
    def ulid(self) -> str:
        return ulid()

    def ulid_bytes(self) -> bytes:
        return ulid_bytes()

    def ulid_timestamp_ms(self, s: str) -> int:
        ts, _ = parse_ulid(s)
        return ts

    # UUID
    def uuid4(self) -> _uuid.UUID:
        return uuid4()

    def uuid7(self) -> _uuid.UUID:
        return uuid7()

    # KSUID
    def ksuid(self) -> KSUID:
        return ksuid()

    # Short IDs
    def short(self, length: int = 21, *, prefix: str = "", alphabet: str = _DEFAULT_ALPHABET) -> str:
        return short_id(length=length, alphabet=alphabet, prefix=prefix)

    def short_fp(self, length: int = 21, *, alphabet: str = _DEFAULT_ALPHABET) -> str:
        return short_id_with_fingerprint(length=length, alphabet=alphabet)

    # Snowflake
    def snowflake(self) -> int:
        return self.snowflake.next_id()

# Глобальный экземпляр
DEFAULT_IDGEN = IdGen()

# =============================================================================
# Примеры использования (не исполняются при импорте)
# =============================================================================

if __name__ == "__main__":
    g = DEFAULT_IDGEN
    print("ULID:", g.ulid())
    u7 = g.uuid7()
    print("UUIDv7:", str(u7))
    k = g.ksuid()
    print("KSUID:", str(k), "ts:", ksuid_datetime(k).isoformat())
    print("Short:", g.short())
    print("Short+FP:", g.short_fp())
    print("Snowflake:", g.snowflake())
