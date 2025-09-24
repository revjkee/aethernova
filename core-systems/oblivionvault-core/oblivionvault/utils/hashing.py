# oblivionvault-core/oblivionvault/utils/hashing.py
"""
Общая криптографическая утилита для OblivionVault:
- Единый интерфейс хэширования (BLAKE3/BLAKE2b/SHA-256) с инкрементальным API.
- One-shot/stream/file хэширование с гарантированными дефолтами.
- Merkle-дерево по чанкам (лист = хэш чанка тем же алгоритмом).
- Каноническое JSON-хэширование (детерминированная сериализация).
- HMAC (SHA-256), HKDF (RFC 5869), константное сравнение.
- Асинхронный подсчёт хэша по AsyncIterator[bytes].

Безопасная деградация:
- При отсутствии пакета blake3 автоматически используется BLAKE2b (digest_size=32),
  далее SHA-256. Алгоритм выбирается явно через HashAlgo; auto_best() возвращает
  максимально сильный доступный из предпочтений.

Замечание:
- Для BLAKE3 поддерживается keyed hashing. Для BLAKE2b — встроенный keyed режим.
- Для SHA-256 keyed-режим реализуется через HMAC.
"""

from __future__ import annotations

import asyncio
import hmac
import hashlib
import json
import math
import mmap
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, Optional, Tuple, Union, AsyncIterator, List

# ----- Опциональная поддержка blake3 -----
try:
    import blake3  # type: ignore
    _HAS_BLAKE3 = True
except Exception:
    _HAS_BLAKE3 = False


# ----- Алгоритмы -----

class HashAlgo(str, Enum):
    BLAKE3 = "blake3"
    BLAKE2B = "blake2b"
    SHA256 = "sha256"

    @classmethod
    def auto_best(cls) -> "HashAlgo":
        """Выбрать лучший доступный алгоритм (BLAKE3 -> BLAKE2b -> SHA256)."""
        if _HAS_BLAKE3:
            return cls.BLAKE3
        # hashlib всегда доступен
        return cls.BLAKE2B  # по умолчанию сильнее/быстрее SHA-256 на больших блоках


DEFAULT_DIGEST_SIZE = 32  # 256 бит для BLAKE3/BLAKE2b; для SHA-256 фиксировано


# ----- Унифицированный инкрементальный Hasher -----

@dataclass
class _State:
    algo: HashAlgo
    digest_size: int
    keyed: bool = False


class Hasher:
    """
    Унифицированный обёртчик для blake3/blake2b/sha256 (или HMAC(sha256) при key).
    Поддерживает update(), digest(), hexdigest(), copy().
    """
    __slots__ = ("_state", "_inner")

    def __init__(self, algo: HashAlgo, *, digest_size: Optional[int] = None, key: Optional[bytes] = None):
        ds = digest_size or DEFAULT_DIGEST_SIZE

        if algo == HashAlgo.BLAKE3:
            if not _HAS_BLAKE3:
                # безопасная деградация
                algo = HashAlgo.BLAKE2B
            else:
                # keyed blake3, если key задан
                self._inner = blake3.blake3(key=key) if key else blake3.blake3()
                # b3 digest_size задаётся при вызове digest(length)
                self._state = _State(algo=HashAlgo.BLAKE3, digest_size=ds, keyed=bool(key))
                return

        if algo == HashAlgo.BLAKE2B:
            # keyed режим встроен
            self._inner = hashlib.blake2b(digest_size=ds, key=key or b"")
            self._state = _State(algo=HashAlgo.BLAKE2B, digest_size=ds, keyed=bool(key))
            return

        if algo == HashAlgo.SHA256:
            # keyed => HMAC(sha256); иначе обычный sha256
            if key:
                self._inner = hmac.new(key, digestmod=hashlib.sha256)
                self._state = _State(algo=HashAlgo.SHA256, digest_size=32, keyed=True)
            else:
                self._inner = hashlib.sha256()
                self._state = _State(algo=HashAlgo.SHA256, digest_size=32, keyed=False)
            return

        raise ValueError(f"Unsupported algo: {algo}")

    def update(self, data: Union[bytes, bytearray, memoryview]) -> None:
        self._inner.update(data)

    def digest(self) -> bytes:
        if self._state.algo == HashAlgo.BLAKE3:
            # blake3 поддерживает переменную длину
            return self._inner.digest(length=self._state.digest_size)
        return self._inner.digest()

    def hexdigest(self) -> str:
        if self._state.algo == HashAlgo.BLAKE3:
            return self._inner.hexdigest(length=self._state.digest_size)
        return self._inner.hexdigest()

    def copy(self) -> "Hasher":
        c = object.__new__(Hasher)
        object.__setattr__(c, "_inner", self._inner.copy())
        object.__setattr__(c, "_state", _State(**self._state.__dict__))
        return c

    @property
    def algo(self) -> HashAlgo:
        return self._state.algo

    @property
    def digest_size(self) -> int:
        return self._state.digest_size

    @property
    def keyed(self) -> bool:
        return self._state.keyed


# ----- Вспомогательные фабрики -----

def new_hasher(algo: Optional[HashAlgo] = None, *, digest_size: Optional[int] = None, key: Optional[bytes] = None) -> Hasher:
    """Создать новый Hasher с безопасными дефолтами."""
    return Hasher(algo or HashAlgo.auto_best(), digest_size=digest_size, key=key)


# ----- One-shot хэширование -----

def hash_bytes(data: Union[bytes, bytearray, memoryview], algo: Optional[HashAlgo] = None, *, digest_size: Optional[int] = None, key: Optional[bytes] = None) -> str:
    """Хэш массива байт; возвращает hex-строку."""
    h = new_hasher(algo, digest_size=digest_size, key=key)
    h.update(data)
    return h.hexdigest()


def hash_text(text: str, algo: Optional[HashAlgo] = None, *, digest_size: Optional[int] = None, key: Optional[bytes] = None, encoding: str = "utf-8") -> str:
    """Хэш строки (utf-8 по умолчанию)."""
    return hash_bytes(text.encode(encoding), algo, digest_size=digest_size, key=key)


# ----- Канонический JSON-хэш -----

def canonical_json_dumps(obj: object) -> bytes:
    """
    Детерминированная сериализация:
    - sort_keys=True
    - separators=(",", ":") (без лишних пробелов)
    - ensure_ascii=False (стабильная бинарная форма UTF-8)
    """
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def hash_canonical_json(obj: object, algo: Optional[HashAlgo] = None, *, digest_size: Optional[int] = None, key: Optional[bytes] = None) -> str:
    """Хэш канонического JSON-представления объекта."""
    payload = canonical_json_dumps(obj)
    return hash_bytes(payload, algo, digest_size=digest_size, key=key)


# ----- Потоковое и файловое хэширование -----

def hash_stream(stream, algo: Optional[HashAlgo] = None, *, digest_size: Optional[int] = None, key: Optional[bytes] = None, chunk_size: int = 4 * 1024 * 1024) -> Tuple[str, int]:
    """
    Хэш произвольного побайтового потока (file-like .read()).
    Возвращает (hex, total_size).
    """
    h = new_hasher(algo, digest_size=digest_size, key=key)
    total = 0
    while True:
        b = stream.read(chunk_size)
        if not b:
            break
        total += len(b)
        h.update(b)
    return h.hexdigest(), total


def hash_file(path: Union[str, Path], algo: Optional[HashAlgo] = None, *, digest_size: Optional[int] = None, key: Optional[bytes] = None, chunk_size: int = 4 * 1024 * 1024, use_mmap: bool = True) -> str:
    """
    Хэш файла с опциональным memory-map (для больших файлов). Возвращает hex.
    """
    p = Path(path)
    h = new_hasher(algo, digest_size=digest_size, key=key)

    with p.open("rb") as f:
        if use_mmap and p.stat().st_size > 0:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                view = memoryview(mm)
                for off in range(0, len(view), chunk_size):
                    h.update(view[off:off + chunk_size])
        else:
            while True:
                b = f.read(chunk_size)
                if not b:
                    break
                h.update(b)
    return h.hexdigest()


# ----- Merkle-дерево по чанкам -----

def _leaf_digest(chunk: bytes, algo: HashAlgo, digest_size: int) -> bytes:
    if algo == HashAlgo.BLAKE3 and _HAS_BLAKE3:
        return blake3.blake3(chunk).digest(length=digest_size)
    if algo == HashAlgo.BLAKE2B:
        return hashlib.blake2b(chunk, digest_size=digest_size).digest()
    # SHA-256 фикс. длины
    return hashlib.sha256(chunk).digest()


def _node_digest(a: bytes, b: bytes, algo: HashAlgo, digest_size: int) -> bytes:
    if algo == HashAlgo.BLAKE3 and _HAS_BLAKE3:
        return blake3.blake3(a + b).digest(length=digest_size)
    if algo == HashAlgo.BLAKE2B:
        return hashlib.blake2b(a + b, digest_size=digest_size).digest()
    return hashlib.sha256(a + b).digest()


def merkle_root_from_leaves(leaves: Iterable[bytes], algo: Optional[HashAlgo] = None, *, digest_size: int = DEFAULT_DIGEST_SIZE) -> str:
    """
    Построить корень Меркла из уже посчитанных хэшей листьев (bytes).
    Дублируем последний элемент при нечётном числе узлов.
    Возвращает hex-строку корня; для пустого — "".
    """
    algo = algo or HashAlgo.auto_best()
    level: List[bytes] = list(leaves)
    if not level:
        return ""
    while len(level) > 1:
        nxt: List[bytes] = []
        it = iter(level)
        for a in it:
            try:
                b = next(it)
            except StopIteration:
                b = a
            nxt.append(_node_digest(a, b, algo, digest_size))
        level = nxt
    return level[0].hex()


def hash_stream_with_merkle(stream, algo: Optional[HashAlgo] = None, *, digest_size: int = DEFAULT_DIGEST_SIZE, chunk_size: int = 4 * 1024 * 1024) -> Tuple[str, str, int]:
    """
    Подсчитать content-хэш потока + Merkle-корень по чанкам.
    Возвращает (content_hex, merkle_hex, total_size).
    """
    algo = algo or HashAlgo.auto_best()
    h = new_hasher(algo, digest_size=digest_size)
    leaves: List[bytes] = []
    total = 0
    while True:
        c = stream.read(chunk_size)
        if not c:
            break
        total += len(c)
        h.update(c)
        leaves.append(_leaf_digest(c, algo, digest_size))
    return h.hexdigest(), merkle_root_from_leaves(leaves, algo, digest_size=digest_size), total


async def async_hash_bytes_iter(chunks: AsyncIterator[bytes], algo: Optional[HashAlgo] = None, *, digest_size: int = DEFAULT_DIGEST_SIZE, chunk_size: int = 4 * 1024 * 1024) -> Tuple[str, str, int]:
    """
    Асинхронный подсчёт content-хэша и Merkle-корня по асинхронному итератору байтов.
    Возвращает (content_hex, merkle_hex, total_size).
    """
    algo = algo or HashAlgo.auto_best()
    h = new_hasher(algo, digest_size=digest_size)
    leaves: List[bytes] = []
    total = 0
    async for c in chunks:
        if not c:
            continue
        total += len(c)
        h.update(c)
        leaves.append(_leaf_digest(c, algo, digest_size))
    return h.hexdigest(), merkle_root_from_leaves(leaves, algo, digest_size=digest_size), total


# ----- HMAC / HKDF -----

def hmac_sha256_hex(key: bytes, data: Union[bytes, bytearray, memoryview]) -> str:
    """HMAC-SHA256 в hex-представлении."""
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def hkdf_extract(salt: Optional[bytes], ikm: bytes, hashmod=hashlib.sha256) -> bytes:
    """
    HKDF-Extract (RFC 5869): PRK = HMAC-Hash(salt, IKM)
    Если salt is None, используется нулевая строка длины hash_len.
    """
    hash_len = hashmod().digest_size
    if salt is None:
        salt = bytes([0] * hash_len)
    return hmac.new(salt, ikm, hashmod).digest()


def hkdf_expand(prk: bytes, info: Optional[bytes], length: int, hashmod=hashlib.sha256) -> bytes:
    """
    HKDF-Expand (RFC 5869): вывод ключевого материала длиной 'length'.
    """
    if length <= 0:
        return b""
    hash_len = hashmod().digest_size
    n = math.ceil(length / hash_len)
    if n > 255:
        raise ValueError("HKDF length too large")
    t = b""
    okm = b""
    info = info or b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashmod).digest()
        okm += t
    return okm[:length]


# ----- Константное сравнение -----

def constant_time_eq(a: Union[bytes, str], b: Union[bytes, str]) -> bool:
    """
    Безопасное сравнение, устойчивое к тайминговым атакам.
    Принимает bytes или hex-строки.
    """
    if isinstance(a, str) and isinstance(b, str):
        return hmac.compare_digest(a, b)
    if isinstance(a, (bytes, bytearray, memoryview)) and isinstance(b, (bytes, bytearray, memoryview)):
        return hmac.compare_digest(bytes(a), bytes(b))
    # если типы различны, приводим к bytes/hex по возможности
    if isinstance(a, str):
        try:
            a = bytes.fromhex(a)
        except Exception:
            a = a.encode("utf-8")
    if isinstance(b, str):
        try:
            b = bytes.fromhex(b)
        except Exception:
            b = b.encode("utf-8")
    return hmac.compare_digest(bytes(a), bytes(b))


# ----- Утилиты выбора/проверки -----

def ensure_algo(algo: Optional[HashAlgo]) -> HashAlgo:
    """Вернуть алгоритм с учётом auto_best()."""
    return algo or HashAlgo.auto_best()


def is_blake3_available() -> bool:
    return _HAS_BLAKE3


# ----- Публичные символы -----

__all__ = [
    "HashAlgo",
    "Hasher",
    "new_hasher",
    "hash_bytes",
    "hash_text",
    "canonical_json_dumps",
    "hash_canonical_json",
    "hash_stream",
    "hash_file",
    "merkle_root_from_leaves",
    "hash_stream_with_merkle",
    "async_hash_bytes_iter",
    "hmac_sha256_hex",
    "hkdf_extract",
    "hkdf_expand",
    "constant_time_eq",
    "ensure_algo",
    "is_blake3_available",
    "DEFAULT_DIGEST_SIZE",
]
