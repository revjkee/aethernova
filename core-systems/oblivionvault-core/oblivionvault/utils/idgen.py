"""
oblivionvault.utils.idgen
Промышленный генератор идентификаторов: ULID (монотонический) и UUIDv7.

Особенности:
- Без внешних зависимостей (stdlib only)
- Потокобезопасность
- Невозвратный источник времени (регресс часов компенсируется оффсетом)
- Стратегии: "ulid" (48b ts + 80b rnd), "uuid7" (60b ts + 62b rnd)
- Кодеки: base32 (Crockford, фикс. 26), base62 (22 для 128 бит, при fixed_len), base64url (22, без '='), hex, uuid
- Префикс + разделитель
- Извлечение timestamp (мс) из ULID/UUIDv7 независимо от кодека
- Валидация и парсинг с учётом префикса

Договорённости:
- Все времена — Unix epoch в миллисекундах
- Монотоничность: при совпадении ts_ms случайная часть инкрементируется по модулю
- Для UUIDv7 поддержан монотонический инкремент 62-битной энтропии
"""

from __future__ import annotations

import os
import time
import secrets
import threading
from dataclasses import dataclass
from typing import Optional, Tuple, Literal

__all__ = [
    "IdGenConfig",
    "IdGenerator",
    "encode_base32_crockford",
    "decode_base32_crockford",
    "encode_base62",
    "decode_base62",
    "encode_base64url_nopad",
    "decode_base64url_nopad",
    "is_valid_encoded",
]

# ------------------------- Алфавиты и кодеки -------------------------

_B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford, без I L O U
_B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

def _int_to_base(n: int, alphabet: str) -> str:
    if n < 0:
        raise ValueError("negative not supported")
    base = len(alphabet)
    if n == 0:
        return alphabet[0]
    out = []
    while n:
        n, r = divmod(n, base)
        out.append(alphabet[r])
    return "".join(reversed(out))

def _base_to_int(s: str, alphabet: str) -> int:
    base = len(alphabet)
    lookup = {ch: i for i, ch in enumerate(alphabet)}
    n = 0
    for ch in s:
        try:
            v = lookup[ch]
        except KeyError as e:
            raise ValueError(f"invalid char {ch!r}") from e
        n = n * base + v
    return n

def encode_base32_crockford(data: bytes, fixed_len: Optional[int] = None) -> str:
    n = int.from_bytes(data, "big")
    s = _int_to_base(n, _B32)
    if fixed_len is not None:
        s = s.rjust(fixed_len, _B32[0])
    return s

def decode_base32_crockford(s: str, expected_len_bytes: Optional[int] = None) -> bytes:
    n = _base_to_int(s, _B32)
    if expected_len_bytes is None:
        # округление до ближайшего количества байт
        blen = max(1, (n.bit_length() + 7) // 8)
    else:
        blen = expected_len_bytes
    return n.to_bytes(blen, "big")

def encode_base62(data: bytes, fixed_len: Optional[int] = None) -> str:
    n = int.from_bytes(data, "big")
    s = _int_to_base(n, _B62)
    if fixed_len is not None:
        s = s.rjust(fixed_len, _B62[0])
    return s

def decode_base62(s: str, expected_len_bytes: Optional[int] = None) -> bytes:
    n = _base_to_int(s, _B62)
    if expected_len_bytes is None:
        blen = max(1, (n.bit_length() + 7) // 8)
    else:
        blen = expected_len_bytes
    return n.to_bytes(blen, "big")

def encode_base64url_nopad(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

def decode_base64url_nopad(s: str) -> bytes:
    import base64
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)

def is_valid_encoded(s: str, alphabet: str) -> bool:
    return all(ch in alphabet for ch in s)

# ------------------------- Безопасный источник времени -------------------------

class _SafeTimeSource:
    """
    Невозвратный источник времени в миллисекундах.
    Компенсирует регресс системного времени через локальный смещающий оффсет.
    Потокобезопасен.
    """
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._offset_ms = 0
        self._last_real_ms = self._real_ms()

    @staticmethod
    def _real_ms() -> int:
        return time.time_ns() // 1_000_000

    def now_ms(self) -> int:
        with self._lock:
            cur = self._real_ms()
            if cur < self._last_real_ms:
                # регресс часов — увеличиваем оффсет
                self._offset_ms += (self._last_real_ms - cur)
            self._last_real_ms = max(cur, self._last_real_ms)
            return self._last_real_ms + self._offset_ms

# ------------------------- Конфигурация -------------------------

Encoding = Literal["base32", "base62", "base64", "hex", "uuid"]
Strategy = Literal["ulid", "uuid7"]

@dataclass(frozen=True)
class IdGenConfig:
    strategy: Strategy = "uuid7"
    encoding: Encoding = "base62"
    prefix: Optional[str] = None
    sep: str = "_"
    uppercase: bool = False
    fixed_len: bool = True  # применять фиксированную длину для base32/base62
    monotonic: bool = True  # монотоничность при совпадении ts
    # фиксированные длины для 128-бит идентификаторов
    fixed_len_base62_128: int = 22
    fixed_len_base64_128: int = 22  # base64url без паддинга
    fixed_len_base32_ulid: int = 26

# ------------------------- Внутренние состояния стратегий -------------------------

class _UlidState:
    """
    ULID: 48 бит времени (мс) + 80 бит rnd.
    При одинаковом ts_ms инкрементируем 80-битную случайность по модулю 2^80.
    """
    def __init__(self, time_source: _SafeTimeSource, monotonic: bool) -> None:
        self._ts = time_source
        self._lock = threading.Lock()
        self._last_ts: int = -1
        self._last_rnd80: int = secrets.randbits(80)
        self._monotonic = monotonic

    def new_bytes(self) -> Tuple[bytes, int]:
        ts = self._ts.now_ms()
        with self._lock:
            if ts == self._last_ts and self._monotonic:
                self._last_rnd80 = (self._last_rnd80 + 1) & ((1 << 80) - 1)
            else:
                self._last_ts = ts
                self._last_rnd80 = secrets.randbits(80)
            rnd80 = self._last_rnd80

        if ts >= (1 << 48):
            raise OverflowError("timestamp exceeds 48-bit capacity for ULID")
        id_int = (ts << 80) | rnd80
        return id_int.to_bytes(16, "big"), ts

class _Uuid7State:
    """
    UUIDv7: 60 бит времени (мс) + 62 бит rnd (разложены: 14 бит в clock_seq, 48 бит в node).
    При одинаковом ts_ms инкрементируем 62-битный счётчик по модулю 2^62.
    """
    def __init__(self, time_source: _SafeTimeSource, monotonic: bool) -> None:
        self._ts = time_source
        self._lock = threading.Lock()
        self._last_ts: int = -1
        self._last_r62: int = secrets.randbits(62)
        self._monotonic = monotonic

    @staticmethod
    def _pack_uuid7(ts_ms: int, r62: int) -> bytes:
        if ts_ms >= (1 << 60):
            raise OverflowError("timestamp exceeds 60-bit capacity for UUIDv7")

        time_low = ts_ms & 0xFFFFFFFF
        time_mid = (ts_ms >> 32) & 0xFFFF
        time_hi = (ts_ms >> 48) & 0x0FFF  # 12 бит
        time_hi_and_version = (0x7 << 12) | time_hi  # версия 7

        # 62 бита случайности
        r62 &= (1 << 62) - 1
        r14 = (r62 >> 48) & 0x3FFF
        r48 = r62 & ((1 << 48) - 1)

        clock_seq_hi = (r14 >> 8) & 0x3F
        clock_seq_hi_and_reserved = 0x80 | clock_seq_hi  # variant 10xxxxxx
        clock_seq_low = r14 & 0xFF

        node = r48

        b = bytearray(16)
        b[0:4] = time_low.to_bytes(4, "big")
        b[4:6] = time_mid.to_bytes(2, "big")
        b[6:8] = time_hi_and_version.to_bytes(2, "big")
        b[8] = clock_seq_hi_and_reserved
        b[9] = clock_seq_low
        b[10:16] = node.to_bytes(6, "big")
        return bytes(b)

    def new_bytes(self) -> Tuple[bytes, int]:
        ts = self._ts.now_ms()
        with self._lock:
            if ts == self._last_ts and self._monotonic:
                self._last_r62 = (self._last_r62 + 1) & ((1 << 62) - 1)
            else:
                self._last_ts = ts
                self._last_r62 = secrets.randbits(62)
            r62 = self._last_r62

        return self._pack_uuid7(ts, r62), ts

# ------------------------- Утилиты разбора timestamp -------------------------

def _ulid_ts_ms_from_bytes(b: bytes) -> int:
    if len(b) != 16:
        raise ValueError("expected 16 bytes")
    id_int = int.from_bytes(b, "big")
    return id_int >> 80  # верхние 48 бит — timestamp

def _uuid7_ts_ms_from_bytes(b: bytes) -> int:
    if len(b) != 16:
        raise ValueError("expected 16 bytes")
    time_low = int.from_bytes(b[0:4], "big")
    time_mid = int.from_bytes(b[4:6], "big")
    time_hi_and_version = int.from_bytes(b[6:8], "big")
    ts = ((time_hi_and_version & 0x0FFF) << 48) | (time_mid << 32) | time_low
    return ts

def _uuid_bytes_to_str(b: bytes) -> str:
    # Каноническая форма 8-4-4-4-12 (hex, lower)
    hexs = b.hex()
    return f"{hexs[0:8]}-{hexs[8:12]}-{hexs[12:16]}-{hexs[16:20]}-{hexs[20:32]}"

def _uuid_str_to_bytes(s: str) -> bytes:
    h = s.replace("-", "")
    if len(h) != 32:
        raise ValueError("invalid uuid length")
    return bytes.fromhex(h)

# ------------------------- Основной класс генератора -------------------------

class IdGenerator:
    """
    Генератор идентификаторов.
    """
    def __init__(self, config: Optional[IdGenConfig] = None) -> None:
        self.cfg = config or IdGenConfig()
        self._time = _SafeTimeSource()
        if self.cfg.strategy == "ulid":
            self._st = _UlidState(self._time, self.cfg.monotonic)
        elif self.cfg.strategy == "uuid7":
            self._st = _Uuid7State(self._time, self.cfg.monotonic)
        else:
            raise ValueError("unsupported strategy")

    # -------- Публичные методы --------

    def new_id(self) -> str:
        raw, _ = self._new_bytes_and_ts()
        encoded = self._encode(raw)
        if self.cfg.uppercase:
            encoded = encoded.upper()
        if self.cfg.prefix:
            return f"{self.cfg.prefix}{self.cfg.sep}{encoded}"
        return encoded

    def new_bytes(self) -> bytes:
        raw, _ = self._new_bytes_and_ts()
        return raw

    def new_raw_with_ts(self) -> Tuple[str, int]:
        raw, ts = self._new_bytes_and_ts()
        encoded = self._encode(raw)
        if self.cfg.uppercase:
            encoded = encoded.upper()
        if self.cfg.prefix:
            encoded = f"{self.cfg.prefix}{self.cfg.sep}{encoded}"
        return encoded, ts

    def parse_timestamp_ms(self, identifier: str) -> int:
        body = self._strip_prefix(identifier)
        raw = self._decode(body)
        if self.cfg.strategy == "ulid":
            return _ulid_ts_ms_from_bytes(raw)
        else:
            return _uuid7_ts_ms_from_bytes(raw)

    def validate(self, identifier: str) -> bool:
        try:
            body = self._strip_prefix(identifier)
            _ = self._decode(body)
            return True
        except Exception:
            return False

    # -------- Вспомогательные --------

    def _new_bytes_and_ts(self) -> Tuple[bytes, int]:
        return self._st.new_bytes()

    def _strip_prefix(self, s: str) -> str:
        if self.cfg.prefix:
            p = f"{self.cfg.prefix}{self.cfg.sep}"
            if s.startswith(p):
                return s[len(p):]
            # если префикс задан, но строка без него — считаем невалидной
            raise ValueError("missing required prefix")
        return s

    def _encode(self, data: bytes) -> str:
        enc = self.cfg.encoding
        if enc == "uuid":
            # актуально и для ULID, и для UUIDv7 — всегда 16 байт; просто UUID-форма
            return _uuid_bytes_to_str(data)
        if enc == "hex":
            return data.hex()
        if enc == "base64":
            return encode_base64url_nopad(data)
        if enc == "base32":
            # ULID требует 26 символов
            fixed = self.cfg.fixed_len_base32_ulid if self.cfg.fixed_len else None
            return encode_base32_crockford(data, fixed_len=fixed)
        if enc == "base62":
            fixed = self.cfg.fixed_len_base62_128 if self.cfg.fixed_len else None
            return encode_base62(data, fixed_len=fixed)
        raise ValueError("unsupported encoding")

    def _decode(self, s: str) -> bytes:
        enc = self.cfg.encoding
        if enc == "uuid":
            return _uuid_str_to_bytes(s)
        if enc == "hex":
            b = bytes.fromhex(s)
            if len(b) != 16:
                raise ValueError("invalid hex length for 128-bit id")
            return b
        if enc == "base64":
            b = decode_base64url_nopad(s)
            if len(b) != 16:
                raise ValueError("invalid base64url length for 128-bit id")
            return b
        if enc == "base32":
            b = decode_base32_crockford(s, expected_len_bytes=16)
            if len(b) != 16:
                raise ValueError("invalid base32 length for 128-bit id")
            return b
        if enc == "base62":
            b = decode_base62(s, expected_len_bytes=16)
            if len(b) != 16:
                raise ValueError("invalid base62 length for 128-bit id")
            return b
        raise ValueError("unsupported encoding")
