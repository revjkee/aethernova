# -*- coding: utf-8 -*-
"""
ledger.crypto.hashing — промышленный слой хеширования для Ledger Core.

Возможности:
- Единый реестр алгоритмов: sha256, sha512_256, keccak256*, blake3*
- Потоковое и файловое хеширование с фиксированным размером чанка
- Константное сравнение (timing-safe)
- HMAC (RFC 2104) и HKDF (RFC 5869)
- Merkle-дерево (дерево сумм) с генерацией/проверкой доказательств
- Упрощённый multihash-представитель (code|length|digest)
- Безопасные деградации при отсутствии опциональных зависимостей
- Строгая типизация, проверяемые исключения

Зависимости (базовые): Python 3.10+, hashlib, hmac
Опциональные:
    - keccak256: pysha3 (pip install pysha3)
    - blake3:    blake3 (pip install blake3)

© MIT
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import io
import os
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Iterable, List, Optional, Tuple, Union

try:
    import sha3  # type: ignore  # pysha3
    _HAS_KECCAK = True
except Exception:
    _HAS_KECCAK = False

try:
    import blake3  # type: ignore
    _HAS_BLAKE3 = True
except Exception:
    _HAS_BLAKE3 = False


# ============================ Исключения ============================

class HashingError(Exception):
    pass

class UnsupportedAlgorithm(HashingError):
    pass

class VerificationError(HashingError):
    pass


# ============================ Алгоритмы и реестр ============================

class HashAlg(str, Enum):
    sha256 = "sha256"
    sha512_256 = "sha512_256"      # SHA-512/256 (truncated)
    keccak256 = "keccak256"        # требует pysha3
    blake3 = "blake3"              # требует blake3

@dataclass(frozen=True)
class HashInfo:
    name: HashAlg
    digest_size: int
    block_size: int

# Фабрика хешеров: возвращает объект со стандартным API update()/digest()/hexdigest()
HasherFactory = Callable[[], "BaseHasher"]

def _sha256_factory() -> "BaseHasher":
    return _WrapHash(hashlib.sha256())

def _sha512_256_factory() -> "BaseHasher":
    # hashlib.sha512 truncation 256 (sha512_256) доступен как алгоритм "sha512_256" в новых OpenSSL,
    # но для переносимости используем общий способ: hashlib.new("sha512_256") при наличии, иначе truncate.
    try:
        return _WrapHash(hashlib.new("sha512_256"))
    except Exception:
        # Fallback: truncate SHA-512 (по стандарту SHA-512/256 отличается I.V., так что этот fallback допустим
        # только если OpenSSL не предоставляет родной алгоритм. Для совместимости — явно помечено.)
        return _TruncateHash(hashlib.sha512(), 32)

def _keccak256_factory() -> "BaseHasher":
    if not _HAS_KECCAK:
        raise UnsupportedAlgorithm("keccak256 requires 'pysha3' package")
    return _WrapHash(sha3.keccak_256())

def _blake3_factory() -> "BaseHasher":
    if not _HAS_BLAKE3:
        raise UnsupportedAlgorithm("blake3 requires 'blake3' package")
    return _Blake3Wrapper(blake3.blake3())

_REGISTRY: dict[HashAlg, Tuple[HashInfo, HasherFactory]] = {
    HashAlg.sha256: (HashInfo(HashAlg.sha256, 32, hashlib.sha256().block_size), _sha256_factory),
    HashAlg.sha512_256: (HashInfo(HashAlg.sha512_256, 32, 128), _sha512_256_factory),
    HashAlg.keccak256: (HashInfo(HashAlg.keccak256, 32, 136), _keccak256_factory),
    HashAlg.blake3: (HashInfo(HashAlg.blake3, 32, 64), _blake3_factory),
}


# ============================ Обёртки над реализациями ============================

class BaseHasher:
    def update(self, data: bytes) -> None: ...
    def digest(self) -> bytes: ...
    def hexdigest(self) -> str: ...

class _WrapHash(BaseHasher):
    def __init__(self, h):
        self._h = h
    def update(self, data: bytes) -> None:
        self._h.update(data)
    def digest(self) -> bytes:
        return self._h.digest()
    def hexdigest(self) -> str:
        return self._h.hexdigest()

class _TruncateHash(BaseHasher):
    """Обёртка, отбрасывающая digest до n байт."""
    def __init__(self, h, n: int):
        self._h = h
        self._n = n
    def update(self, data: bytes) -> None:
        self._h.update(data)
    def digest(self) -> bytes:
        return self._h.digest()[: self._n]
    def hexdigest(self) -> str:
        return self.digest().hex()

class _Blake3Wrapper(BaseHasher):
    def __init__(self, ctx):
        self._ctx = ctx
    def update(self, data: bytes) -> None:
        self._ctx.update(data)
    def digest(self) -> bytes:
        return self._ctx.digest(length=32)
    def hexdigest(self) -> str:
        return self.digest().hex()


# ============================ Вспомогательные функции ============================

def get_info(alg: HashAlg) -> HashInfo:
    try:
        return _REGISTRY[alg][0]
    except KeyError:
        raise UnsupportedAlgorithm(str(alg))

def new_hasher(alg: HashAlg) -> BaseHasher:
    if alg not in _REGISTRY:
        raise UnsupportedAlgorithm(str(alg))
    _, factory = _REGISTRY[alg]
    return factory()

def digest(data: bytes, alg: HashAlg = HashAlg.sha256) -> bytes:
    h = new_hasher(alg)
    h.update(data)
    return h.digest()

def hexdigest(data: bytes, alg: HashAlg = HashAlg.sha256) -> str:
    return digest(data, alg).hex()

def timing_safe_equal(a: bytes, b: bytes) -> bool:
    # Константное сравнение
    return _hmac.compare_digest(a, b)

# ---------------- Files & streaming ----------------

DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB

def hash_stream(stream: io.BufferedReader, alg: HashAlg = HashAlg.sha256, chunk_size: int = DEFAULT_CHUNK_SIZE) -> bytes:
    h = new_hasher(alg)
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        h.update(chunk)
    return h.digest()

def hash_file(path: Union[str, os.PathLike], alg: HashAlg = HashAlg.sha256, chunk_size: int = DEFAULT_CHUNK_SIZE) -> bytes:
    with open(path, "rb", buffering=chunk_size) as f:
        return hash_stream(f, alg=alg, chunk_size=chunk_size)

# Асинхронная обёртка (без дополнительных зависимостей)
async def hash_file_async(path: Union[str, os.PathLike], alg: HashAlg = HashAlg.sha256, chunk_size: int = DEFAULT_CHUNK_SIZE) -> bytes:
    import asyncio
    return await asyncio.to_thread(hash_file, path, alg, chunk_size)

# ---------------- HMAC & HKDF ----------------

def hmac_digest(key: bytes, data: bytes, alg: HashAlg = HashAlg.sha256) -> bytes:
    info = get_info(alg)
    if alg == HashAlg.sha256:
        _name = "sha256"
    elif alg == HashAlg.sha512_256:
        # Используем базовую SHA-512, затем тримминг: HMAC вычисляется на полном SHA-512, результат затем усечён.
        # Для совместимости с сторонними реализациями настоятельно рекомендуем sha256/keccak/blake3.
        _name = "sha512"
    elif alg == HashAlg.keccak256:
        if not _HAS_KECCAK:
            raise UnsupportedAlgorithm("keccak256 requires 'pysha3' for HMAC")
        # В HMAC нужен callable; pysha3 предоставляет sha3.keccak_256
        return _hmac.new(key, data, sha3.keccak_256).digest()
    elif alg == HashAlg.blake3:
        if not _HAS_BLAKE3:
            raise UnsupportedAlgorithm("blake3 requires 'blake3' for HMAC-like keyed hashing")
        # У blake3 есть keyed mode; используем его вместо HMAC, чтобы не терять свойства.
        return blake3.blake3(data, key=key).digest(length=info.digest_size)
    else:
        raise UnsupportedAlgorithm(str(alg))

    mac = _hmac.new(key, data, _name).digest()
    return mac[: info.digest_size]

def hkdf_extract(salt: bytes, ikm: bytes, alg: HashAlg = HashAlg.sha256) -> bytes:
    return hmac_digest(salt, ikm, alg=alg)

def hkdf_expand(prk: bytes, info: bytes, length: int, alg: HashAlg = HashAlg.sha256) -> bytes:
    """
    HKDF-Expand (RFC 5869).
    """
    hash_len = get_info(alg).digest_size
    if length <= 0 or length > 255 * hash_len:
        raise HashingError("invalid HKDF length")
    t = b""
    okm = b""
    i = 1
    while len(okm) < length:
        t = hmac_digest(prk, t + info + bytes([i]), alg=alg)
        okm += t
        i += 1
    return okm[:length]

def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int, alg: HashAlg = HashAlg.sha256) -> bytes:
    prk = hkdf_extract(salt, ikm, alg=alg)
    return hkdf_expand(prk, info, length, alg=alg)


# ============================ Merkle-дерево ============================

class MerkleHashOrder(str, Enum):
    lexicographic = "lexicographic"   # сортируем пары лексикографически
    left_right = "left_right"         # чёткое направление (нужно хранить флаг left/right)

@dataclass(frozen=True)
class MerkleProof:
    leaves_count: int
    index: int                      # индекс листа
    path: List[bytes]               # список соседей по уровням
    order: MerkleHashOrder

def _hash_pair(a: bytes, b: bytes, alg: HashAlg, order: MerkleHashOrder) -> bytes:
    if order == MerkleHashOrder.lexicographic:
        left, right = (a, b) if a <= b else (b, a)
    else:
        left, right = a, b
    return digest(left + right, alg=alg)

def merkle_root(leaves: Iterable[bytes], alg: HashAlg = HashAlg.sha256, order: MerkleHashOrder = MerkleHashOrder.lexicographic) -> bytes:
    layer = [digest(x, alg=alg) for x in leaves]
    if not layer:
        # Пустое дерево: по ряду протоколов возвращают хеш пустой строки
        return digest(b"", alg=alg)
    while len(layer) > 1:
        nxt: List[bytes] = []
        it = iter(layer)
        for a in it:
            b = next(it, None)
            if b is None:
                # дублируем последний (распространённая практика в блокчейнах)
                b = a
            nxt.append(_hash_pair(a, b, alg, order))
        layer = nxt
    return layer[0]

def merkle_proof(leaves: List[bytes], index: int, alg: HashAlg = HashAlg.sha256, order: MerkleHashOrder = MerkleHashOrder.lexicographic) -> MerkleProof:
    if index < 0 or index >= len(leaves):
        raise HashingError("invalid leaf index")
    layer = [digest(x, alg=alg) for x in leaves]
    path: List[bytes] = []
    idx = index
    if not layer:
        raise HashingError("cannot build proof for empty tree")
    while len(layer) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(layer), 2):
            a = layer[i]
            b = layer[i + 1] if i + 1 < len(layer) else a
            if i == idx or (i + 1) == idx:
                sibling = b if i == idx else a
                path.append(sibling)
                idx = i // 2
            nxt.append(_hash_pair(a, b, alg, order))
        layer = nxt
    return MerkleProof(leaves_count=len(leaves), index=index, path=path, order=order)

def verify_merkle_proof(leaf: bytes, proof: MerkleProof, root: bytes, alg: HashAlg = HashAlg.sha256) -> bool:
    h = digest(leaf, alg=alg)
    idx = proof.index
    for sib in proof.path:
        if proof.order == MerkleHashOrder.lexicographic:
            # порядок определяется значением
            h = _hash_pair(h, sib, alg, MerkleHashOrder.lexicographic)
        else:
            # left_right: определяем по чётности индекса
            if idx % 2 == 0:
                h = _hash_pair(h, sib, alg, MerkleHashOrder.left_right)
            else:
                h = _hash_pair(sib, h, alg, MerkleHashOrder.left_right)
        idx //= 2
    return timing_safe_equal(h, root)


# ============================ Multihash (упрощённый) ============================

class MultiHashCode(int, Enum):
    # Сопоставления (примерные, для внутреннего использования)
    sha256 = 0x12
    sha512_256 = 0x13
    keccak256 = 0x1b
    blake3 = 0x1e

def multihash(data: bytes, alg: HashAlg = HashAlg.sha256) -> bytes:
    d = digest(data, alg=alg)
    if alg == HashAlg.sha256:
        code = MultiHashCode.sha256
    elif alg == HashAlg.sha512_256:
        code = MultiHashCode.sha512_256
    elif alg == HashAlg.keccak256:
        code = MultiHashCode.keccak256
    elif alg == HashAlg.blake3:
        code = MultiHashCode.blake3
    else:
        raise UnsupportedAlgorithm(str(alg))
    length = len(d)
    # varint можно добавить при необходимости; для простоты — однобайтовая длина до 255
    if length > 255:
        raise HashingError("digest too long for simple multihash")
    return bytes([code]) + bytes([length]) + d

def parse_multihash(mh: bytes) -> Tuple[HashAlg, bytes]:
    if len(mh) < 2:
        raise HashingError("invalid multihash")
    code = mh[0]
    length = mh[1]
    if len(mh) != 2 + length:
        raise HashingError("invalid multihash length")
    body = mh[2:]
    if code == MultiHashCode.sha256:
        alg = HashAlg.sha256
    elif code == MultiHashCode.sha512_256:
        alg = HashAlg.sha512_256
    elif code == MultiHashCode.keccak256:
        alg = HashAlg.keccak256
    elif code == MultiHashCode.blake3:
        alg = HashAlg.blake3
    else:
        raise UnsupportedAlgorithm(f"unknown multihash code {code}")
    return alg, body


# ============================ Константы/проверка окружения ============================

def is_keccak_available() -> bool:
    return _HAS_KECCAK

def is_blake3_available() -> bool:
    return _HAS_BLAKE3


# ============================ Демонстрационный самотест (можно отключить) ============================

if __name__ == "__main__":
    data = b"ledger-core"
    for alg in [HashAlg.sha256, HashAlg.sha512_256, HashAlg.keccak256, HashAlg.blake3]:
        try:
            print(alg.value, hexdigest(data, alg))
        except UnsupportedAlgorithm as e:
            print(alg.value, "UNAVAILABLE:", e)

    # Merkle
    leaves = [b"a", b"b", b"c", b"d", b"e"]
    root = merkle_root(leaves, HashAlg.sha256)
    pr = merkle_proof(leaves, 2, HashAlg.sha256)
    assert verify_merkle_proof(leaves[2], pr, root, HashAlg.sha256)

    # HMAC/HKDF
    mac = hmac_digest(b"key", b"payload")
    okm = hkdf(b"salt", b"ikm", b"info", 42)
    print("HMAC len:", len(mac), "HKDF len:", len(okm))
