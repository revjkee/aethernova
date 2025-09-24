# policy_core/utils/idgen.py
from __future__ import annotations

import os
import time
import uuid
import hmac
import hashlib
import secrets
import socket
import struct
import threading
from typing import Optional, Literal, Tuple, Union

try:
    from pydantic import BaseModel, Field, validator
except Exception as e:  # pragma: no cover
    raise ImportError("pydantic is required for policy_core.utils.idgen") from e

__all__ = [
    "IdGenConfig",
    "IdFactory",
    "new_uuid4",
    "new_ulid",
    "new_snowflake64",
    "content_id",
    "short_token",
    "decode_ulid",
    "SnowflakeClockError",
    "IdGenError",
]

# ================================
# Константы и исключения
# ================================

CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # без I, L, O, U
BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

DEFAULT_EPOCH_MS = 1577836800000  # 2020-01-01T00:00:00Z
ENV_WORKER_ID = "POLICY_CORE_WORKER_ID"  # 0..1023
ENV_EPOCH_MS = "POLICY_CORE_EPOCH_MS"    # целое ms

class IdGenError(Exception):
    """Базовая ошибка генерации ID."""

class SnowflakeClockError(IdGenError):
    """Часы отмотались назад относительно последней выдачи ID."""

# ================================
# Утилиты
# ================================

def _now_ms() -> int:
    return int(time.time() * 1000)

def _b32_crockford_encode(value: int, length: int) -> str:
    """Преобразование числа в строку Crockford Base32 фиксированной длины."""
    base = 32
    chars = []
    v = value
    while v > 0:
        v, rem = divmod(v, base)
        chars.append(CROCKFORD_ALPHABET[rem])
    out = "".join(reversed(chars or ["0"]))
    if len(out) > length:
        # невозможно уместить
        raise IdGenError("Crockford Base32 overflow for requested length")
    return out.rjust(length, "0")

def _b32_crockford_decode(s: str) -> int:
    """Обратное преобразование Crockford Base32 → число."""
    s = s.strip().upper()
    # Дополнительное отображение похожих символов (по Crockford)
    trans = {"I": "1", "L": "1", "O": "0", "U": "V"}  # U не обязателен, но защищаемся
    s = "".join(trans.get(ch, ch) for ch in s)
    val = 0
    for ch in s:
        try:
            d = CROCKFORD_ALPHABET.index(ch)
        except ValueError:
            raise IdGenError(f"Invalid Crockford Base32 char: {ch}")
        val = val * 32 + d
    return val

def _base62_encode_uint(value: int) -> str:
    """Base62 без знака; компактно для Snowflake."""
    if value == 0:
        return "0"
    base = 62
    out = []
    while value:
        value, rem = divmod(value, base)
        out.append(BASE62_ALPHABET[rem])
    return "".join(reversed(out))

def _base62_decode_uint(s: str) -> int:
    base = 62
    val = 0
    for ch in s:
        try:
            idx = BASE62_ALPHABET.index(ch)
        except ValueError:
            raise IdGenError(f"Invalid Base62 char: {ch}")
        val = val * base + idx
    return val

def _secure_random_bytes(n: int) -> bytes:
    return secrets.token_bytes(n)

def _hostname_hash(bits: int = 10) -> int:
    """Стабильный короткий хэш хоста для worker_id по умолчанию."""
    h = hashlib.blake2b(socket.gethostname().encode("utf-8"), digest_size=16).digest()
    val = int.from_bytes(h, "big")
    mask = (1 << bits) - 1
    return val & mask

def _clamp_worker_id(worker_id: int, bits: int = 10) -> int:
    if not (0 <= worker_id < (1 << bits)):
        raise IdGenError(f"worker_id must be in [0, {1<<bits})")
    return worker_id

def _constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))

# ================================
# Конфигурация генератора
# ================================

class IdGenConfig(BaseModel):
    """
    Глобальная конфигурация фабрики идентификаторов.
    """
    default_type: Literal["ulid", "uuid4", "snowflake64"] = Field("ulid", description="Тип ID по умолчанию")
    epoch_ms: int = Field(DEFAULT_EPOCH_MS, description="Эпоха для Snowflake64 в миллисекундах")
    worker_id: int = Field(-1, description="Worker ID 0..1023; -1 ⇒ autodetect (hostname hash)")
    enforce_monotonic_ulid: bool = Field(True, description="Гарантировать монотонию ULID в рамках процесса")

    @validator("epoch_ms")
    def _epoch_nonneg(cls, v: int) -> int:
        if v < 0:
            raise ValueError("epoch_ms must be non-negative")
        return v

    @validator("worker_id")
    def _worker_range_or_auto(cls, v: int) -> int:
        if v == -1:
            return v
        return _clamp_worker_id(v)

    @classmethod
    def from_env(cls) -> "IdGenConfig":
        epoch = int(os.getenv(ENV_EPOCH_MS, DEFAULT_EPOCH_MS))
        wid = os.getenv(ENV_WORKER_ID)
        worker_id = int(wid) if wid is not None else -1
        return cls(epoch_ms=epoch, worker_id=worker_id)

# ================================
# ULID (128 бит) с монотонией
# Спецификация: 48 бит времени (ms since Unix epoch) + 80 бит случайности
# Выдача: 26 символов в Crockford Base32
# ================================

class _UlidState:
    """
    Потокобезопасное состояние ULID для монотонии на 1 ms.
    """
    __slots__ = ("lock", "last_ms", "rand_prefix", "seq16")

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.last_ms: int = -1
        self.rand_prefix: bytes = b""
        self.seq16: int = 0

_ULID_STATE = _UlidState()

def _ulid_bytes(monotonic: bool = True) -> bytes:
    now_ms = _now_ms()
    ts48 = now_ms & ((1 << 48) - 1)
    ts_bytes = ts48.to_bytes(6, "big")

    if not monotonic:
        return ts_bytes + _secure_random_bytes(10)

    with _ULID_STATE.lock:
        if now_ms != _ULID_STATE.last_ms:
            _ULID_STATE.last_ms = now_ms
            _ULID_STATE.rand_prefix = _secure_random_bytes(8)  # 64 бита
            _ULID_STATE.seq16 = secrets.randbelow(1 << 16)
        else:
            _ULID_STATE.seq16 = (_ULID_STATE.seq16 + 1) & 0xFFFF

        # Конструируем 80 бит случайности как 64-битный префикс + 16-битный счётчик
        rand80 = _ULID_STATE.rand_prefix + _ULID_STATE.seq16.to_bytes(2, "big")
        return ts_bytes + rand80  # 16 байт

def _ulid_encode(b16: bytes) -> str:
    if len(b16) != 16:
        raise IdGenError("ULID requires 16 bytes")
    as_int = int.from_bytes(b16, "big")
    return _b32_crockford_encode(as_int, 26)

def decode_ulid(s: str) -> Tuple[int, bytes]:
    """
    Декодирование ULID: возвращает (timestamp_ms, random_10_bytes).
    Бросает IdGenError при некорректном вводе.
    """
    if len(s) != 26:
        raise IdGenError("ULID string must be 26 chars")
    val = _b32_crockford_decode(s)
    b = val.to_bytes(16, "big")
    ts = int.from_bytes(b[:6], "big")
    rnd = b[6:]
    return ts, rnd

def new_ulid(monotonic: bool = True) -> str:
    """
    Возвращает ULID (26 символов, Base32 Crockford).
    """
    return _ulid_encode(_ulid_bytes(monotonic=monotonic))

# ================================
# UUID4 (стандартная криптостойкая)
# ================================

def new_uuid4() -> str:
    return str(uuid.uuid4())

# ================================
# Snowflake64: 64-битный k-сортируемый ID
# Layout: [41b timestamp(ms since epoch)] [10b worker_id] [12b sequence]
# Возврат: Base62-строка без знака (минимальная длина)
# ================================

class _SnowflakeState:
    __slots__ = ("lock", "last_ms", "sequence", "worker_id", "epoch_ms")

    def __init__(self, worker_id: int, epoch_ms: int) -> None:
        self.lock = threading.Lock()
        self.last_ms: int = -1
        self.sequence: int = 0
        self.worker_id = worker_id
        self.epoch_ms = epoch_ms

    def next_id_uint(self) -> int:
        with self.lock:
            now = _now_ms()
            if now < self.last_ms:
                # Часы пошли назад: удерживаемся, пока не догоним
                # (жёсткая политика; альтернативно можно бросить исключение)
                raise SnowflakeClockError(
                    f"System clock moved backwards: now={now}, last={self.last_ms}"
                )
            if now == self.last_ms:
                self.sequence = (self.sequence + 1) & 0xFFF  # 12 бит
                if self.sequence == 0:
                    # Переполнение секвенса — ждём следующий миллисекундный тик
                    while True:
                        now = _now_ms()
                        if now > self.last_ms:
                            break
                    self.last_ms = now
            else:
                self.sequence = secrets.randbelow(1 << 12)  # случайный старт в ms окне
                self.last_ms = now

            ts = (now - self.epoch_ms)
            if ts < 0:
                raise SnowflakeClockError(
                    f"Current time precedes epoch: now={now}, epoch={self.epoch_ms}"
                )
            if ts >= (1 << 41):
                raise IdGenError("Timestamp overflow for 41-bit field")

            wid = self.worker_id & 0x3FF  # 10 бит
            val = (ts << (10 + 12)) | (wid << 12) | self.sequence
            return val

_snowflake_state_lock = threading.Lock()
_snowflake_state: Optional[_SnowflakeState] = None

def _ensure_snowflake_state(worker_id: Optional[int], epoch_ms: Optional[int]) -> _SnowflakeState:
    global _snowflake_state
    with _snowflake_state_lock:
        if _snowflake_state is not None:
            return _snowflake_state
        # worker_id из ENV/конфига/хоста
        cfg = IdGenConfig.from_env()
        if worker_id is None:
            wid = cfg.worker_id if cfg.worker_id != -1 else _hostname_hash(10)
        else:
            wid = worker_id
        wid = _clamp_worker_id(wid, 10)

        ep = epoch_ms if epoch_ms is not None else cfg.epoch_ms
        _snowflake_state = _SnowflakeState(worker_id=wid, epoch_ms=ep)
        return _snowflake_state

def new_snowflake64(worker_id: Optional[int] = None, epoch_ms: Optional[int] = None, as_base62: bool = True) -> str:
    """
    Возвращает Snowflake-совместимый 64-битный ID (k-сорт), по умолчанию в Base62.
    При необходимости можно получить десятичную строку: as_base62=False.
    """
    st = _ensure_snowflake_state(worker_id, epoch_ms)
    val = st.next_id_uint()
    return _base62_encode_uint(val) if as_base62 else str(val)

# ================================
# Контент-адресные ID (детерминированные)
# Формат: <algo>:<base32> или короткий префикс с Base62
# ================================

def content_id(data: Union[bytes, str], algo: Literal["sha256", "blake2b"] = "sha256", bits: int = 128, as_base: Literal["b32", "b62"] = "b32", prefix: Optional[str] = None) -> str:
    """
    Детерминированный ID по содержимому.
    - algo: sha256|blake2b
    - bits: 64..256, по умолчанию 128 (для компактности)
    - as_base: 'b32' (Crockford) или 'b62'
    - prefix: необязательный префикс (например, 'policy')
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    if algo == "sha256":
        d = hashlib.sha256(data).digest()
    elif algo == "blake2b":
        d = hashlib.blake2b(data, digest_size=32).digest()
    else:
        raise IdGenError("Unsupported algo for content_id")

    if not (64 <= bits <= 256):
        raise IdGenError("bits must be between 64 and 256")

    length_bytes = (bits + 7) // 8
    trunc = d[:length_bytes]
    val = int.from_bytes(trunc, "big")

    if as_base == "b32":
        body = _b32_crockford_encode(val, max(1, (bits + 4) // 5))  # 5 бит на символ
    elif as_base == "b62":
        body = _base62_encode_uint(val)
    else:
        raise IdGenError("Unsupported base in content_id")

    if prefix:
        return f"{prefix}:{algo}:{body}"
    return f"{algo}:{body}"

# ================================
# Короткие токены (URL-safe, без '=') для не-криптографических идентификаторов UI
# ================================

def short_token(length: int = 22, alphabet: Optional[str] = None) -> str:
    """
    Криптографически стойкий случайный токен.
    - length: длина строки
    - alphabet: свой алфавит; по умолчанию URL-safe Base62 расширенный
    """
    if alphabet is None:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    # secrets.choice безопасен и устойчив к биасу при разумных алфавитах
    return "".join(secrets.choice(alphabet) for _ in range(length))

# ================================
# Фабрика
# ================================

class IdFactory:
    """
    Высокоуровневая фабрика ID с конфигом. Потокобезопасна.
    """
    def __init__(self, cfg: Optional[IdGenConfig] = None):
        self.cfg = cfg or IdGenConfig.from_env()
        self._ulid_monotonic = bool(self.cfg.enforce_monotonic_ulid)

    def new(self, kind: Optional[Literal["ulid", "uuid4", "snowflake64"]] = None) -> str:
        k = (kind or self.cfg.default_type)
        if k == "ulid":
            return new_ulid(monotonic=self._ulid_monotonic)
        if k == "uuid4":
            return new_uuid4()
        if k == "snowflake64":
            return new_snowflake64()
        raise IdGenError(f"Unknown id kind: {k}")

    def ulid(self) -> str:
        return new_ulid(monotonic=self._ulid_monotonic)

    def uuid4(self) -> str:
        return new_uuid4()

    def snowflake64(self) -> str:
        return new_snowflake64()

# ================================
# Дополнительно: попытка UUIDv7 (если поддерживается интерпретатором)
# RFC 9562 (UUIDv7) доступен в новых версиях Python.
# Мы не реализуем собственную сборку UUIDv7 здесь — используем stdlib при наличии.
# ================================

def try_uuidv7() -> str:
    """
    Возвращает UUIDv7 из стандартной библиотеки, если доступно.
    Иначе бросает IdGenError.
    """
    if hasattr(uuid, "uuid7"):
        return str(getattr(uuid, "uuid7")())  # type: ignore[attr-defined]
    raise IdGenError("uuid.uuid7 is not available in this Python version")
