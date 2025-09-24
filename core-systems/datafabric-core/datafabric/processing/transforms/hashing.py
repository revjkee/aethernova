# -*- coding: utf-8 -*-
"""
DataFabric | hashing.py
Промышленный модуль хэширования для пакетных и потоковых пайплайнов.

Особенности:
- Алгоритмы: sha256, sha512, sha3_256, sha3_512, blake2b (c настраиваемым digest_size)
- Стриминговое хэширование: bytes/chunks/файл/файловый поток
- Быстрое хэширование больших файлов: mmap с fallback на чтение блоками
- Мультихэш за один проход по данным (минимизация IO)
- HMAC (RFC 2104) и BLAKE2b с ключом, salt, person
- Канонический JSON-хэш (детерминированная сериализация)
- Верификация дайджеста и формирование контент-адресных URI (CAS)
- Без внешних зависимостей (hashlib, hmac, mmap, json)

Совместимо с Python 3.10+.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac as _hmac
import io
import json
import logging
import mmap
import os
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Dict, Iterable, Iterator, List, Mapping, Optional, Tuple, Union

__all__ = [
    "HashConfig",
    "HashResult",
    "SUPPORTED_ALGOS",
    "hash_bytes",
    "hash_text",
    "hash_stream",
    "hash_file",
    "hash_json_canonical",
    "multi_hash_stream",
    "hmac_bytes",
    "blake2b_keyed",
    "verify_digest",
    "to_cas_uri",
]

# ---------------------------
# Константы и поддерживаемые алгоритмы
# ---------------------------

# Поддерживаемые имена алгоритмов hashlib + b2b-N (короткая форма для BLAKE2b с digest_size=N)
SUPPORTED_ALGOS: Mapping[str, str] = {
    "sha256": "sha256",
    "sha512": "sha512",
    "sha3_256": "sha3_256",
    "sha3_512": "sha3_512",
    # Специальная обработка BLAKE2b через префикс b2b-<bits>
    # Примеры: b2b-256, b2b-384, b2b-512
}

# Безопасные размеры блоков чтения (баланс IO/CPU)
_DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB
_MIN_CHUNK_SIZE = 64 * 1024        # 64 KiB
_MAX_CHUNK_SIZE = 32 * 1024 * 1024 # 32 MiB

# Порог, после которого имеет смысл пытаться использовать mmap (если возможно)
_MMAP_THRESHOLD = 8 * 1024 * 1024  # 8 MiB

# Алгоритм по умолчанию: быстрый и криптографически стойкий 256‑битный BLAKE2b
_DEFAULT_ALGO = "b2b-256"


# ---------------------------
# Структуры данных
# ---------------------------

@dataclass(frozen=True)
class HashConfig:
    """
    Конфигурация хэширования.
    """
    algo: str = _DEFAULT_ALGO
    chunk_size: int = _DEFAULT_CHUNK_SIZE
    # Для text -> bytes
    encoding: str = "utf-8"
    normalize_newlines: bool = False  # если True, \r\n и \r приводятся к \n
    # Для вывода
    return_base64: bool = False
    uppercase_hex: bool = False

    def normalized_chunk(self) -> int:
        return max(_MIN_CHUNK_SIZE, min(self.chunk_size, _MAX_CHUNK_SIZE))


@dataclass(frozen=True)
class HashResult:
    """
    Результат хэширования.
    """
    algo: str
    hex: str
    b64: Optional[str]
    size_bytes: Optional[int]
    digest_size_bits: int

    def as_multihash(self) -> str:
        """
        Возвращает строку вида "<algo>:<hex>" (удобно для журналирования/манифестов).
        """
        return f"{self.algo}:{self.hex}"


# ---------------------------
# Внутренние утилиты
# ---------------------------

def _is_b2b(algo: str) -> bool:
    return algo.startswith("b2b-") and algo[4:].isdigit()

def _b2b_digest_size_from_algo(algo: str) -> int:
    """
    b2b-256 -> 32 bytes; значение указывается в битах.
    """
    bits = int(algo.split("-", 1)[1])
    if bits % 8 != 0 or not (8 <= bits <= 512):
        raise ValueError(f"Unsupported BLAKE2b digest size (bits): {bits}")
    return bits // 8

def _new_hasher(algo: str) -> "hashlib._Hash":
    """
    Создает объект хэшера по имени алгоритма.
    Поддержка b2b-* (BLAKE2b) и стандартных алгоритмов hashlib.
    """
    if _is_b2b(algo):
        return hashlib.blake2b(digest_size=_b2b_digest_size_from_algo(algo))
    # стандартные имена
    if algo not in SUPPORTED_ALGOS:
        # Проверим напрямую через hashlib (на случай расширений OpenSSL)
        try:
            return hashlib.new(algo)
        except Exception as e:
            raise ValueError(f"Unsupported algorithm: {algo}") from e
    return hashlib.new(SUPPORTED_ALGOS[algo])

def _digest_size_bits(algo: str, h: "hashlib._Hash") -> int:
    if _is_b2b(algo):
        return _b2b_digest_size_from_algo(algo) * 8
    return h.digest_size * 8

def _maybe_normalize_text(s: str, normalize: bool) -> str:
    if not normalize:
        return s
    # Нормализация переводов строк в \n для стабильного дайджеста
    return s.replace("\r\n", "\n").replace("\r", "\n")

def _to_result(algo: str, h: "hashlib._Hash", size_bytes: Optional[int], cfg: HashConfig) -> HashResult:
    hexd = h.hexdigest()
    if cfg.uppercase_hex:
        hexd = hexd.upper()
    b64d = base64.b64encode(h.digest()).decode("ascii") if cfg.return_base64 else None
    return HashResult(
        algo=algo,
        hex=hexd,
        b64=b64d,
        size_bytes=size_bytes,
        digest_size_bits=_digest_size_bits(algo, h),
    )


# ---------------------------
# Публичные функции хэширования
# ---------------------------

def hash_bytes(data: bytes, cfg: Optional[HashConfig] = None) -> HashResult:
    """
    Хэширует массив байт.
    """
    cfg = cfg or HashConfig()
    h = _new_hasher(cfg.algo)
    h.update(data)
    return _to_result(cfg.algo, h, len(data), cfg)


def hash_text(text: str, cfg: Optional[HashConfig] = None) -> HashResult:
    """
    Детерминированно хэширует строку (с опциональной нормализацией переводов строк).
    """
    cfg = cfg or HashConfig()
    s = _maybe_normalize_text(text, cfg.normalize_newlines)
    return hash_bytes(s.encode(cfg.encoding), cfg)


def hash_stream(stream: BinaryIO, cfg: Optional[HashConfig] = None) -> HashResult:
    """
    Хэширует бинарный поток (файл/буфер) блоками.
    """
    cfg = cfg or HashConfig()
    h = _new_hasher(cfg.algo)
    total = 0
    chunk = stream.read(cfg.normalized_chunk())
    while chunk:
        h.update(chunk)
        total += len(chunk)
        chunk = stream.read(cfg.normalized_chunk())
    return _to_result(cfg.algo, h, total, cfg)


def hash_file(path: Union[str, os.PathLike], cfg: Optional[HashConfig] = None) -> HashResult:
    """
    Хэширует файл. Для больших файлов пытается использовать mmap (с fallback на блочное чтение).
    """
    cfg = cfg or HashConfig()
    p = Path(path)
    size = p.stat().st_size
    h = _new_hasher(cfg.algo)

    # Пробуем mmap, если файл достаточно большой и доступен для mmap
    if size >= _MMAP_THRESHOLD:
        with p.open("rb") as f:
            try:
                with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
                    view = memoryview(mm)
                    h.update(view)
            except (BufferError, ValueError, OSError):
                # Fallback на блочное чтение
                f.seek(0)
                return hash_stream(f, cfg)._replace_size(size)
    else:
        with p.open("rb") as f:
            return hash_stream(f, cfg)._replace_size(size)

    return _to_result(cfg.algo, h, size, cfg)


# Добавим "метод" к HashResult без нарушения dataclass immutability
def _hashresult_replace_size(self: HashResult, size: int) -> HashResult:
    return dataclasses.replace(self, size_bytes=size)

setattr(HashResult, "_replace_size", _hashresult_replace_size)


def hash_json_canonical(obj: object, cfg: Optional[HashConfig] = None) -> HashResult:
    """
    Детерминированное хэширование JSON‑совместимого объекта:
    - сортировка ключей
    - компактные разделители
    - ensure_ascii=False, кодировка UTF‑8
    """
    cfg = cfg or HashConfig()
    data = json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode(cfg.encoding)
    return hash_bytes(data, cfg)


def multi_hash_stream(
    stream: BinaryIO,
    algos: List[str],
    chunk_size: int = _DEFAULT_CHUNK_SIZE,
) -> Dict[str, HashResult]:
    """
    Вычисляет несколько хэшей за один проход по потоку.
    Возвращает словарь {algo: HashResult}.

    Пример:
        with open("file.bin", "rb") as f:
            res = multi_hash_stream(f, ["sha256", "sha3_256", "b2b-256"])
    """
    if not algos:
        raise ValueError("algos must not be empty")

    normalized = max(_MIN_CHUNK_SIZE, min(chunk_size, _MAX_CHUNK_SIZE))

    # Создаем хэшеры
    hashers: Dict[str, hashlib._Hash] = {}
    for a in algos:
        hashers[a] = _new_hasher(a)

    total = 0
    chunk = stream.read(normalized)
    while chunk:
        for h in hashers.values():
            h.update(chunk)
        total += len(chunk)
        chunk = stream.read(normalized)

    out: Dict[str, HashResult] = {}
    for a, h in hashers.items():
        out[a] = HashResult(
            algo=a,
            hex=h.hexdigest(),
            b64=None,
            size_bytes=total,
            digest_size_bits=_digest_size_bits(a, h),
        )
    return out


def hmac_bytes(key: bytes, data: bytes, algo: str = "sha256", return_base64: bool = False, uppercase_hex: bool = False) -> Tuple[str, Optional[str]]:
    """
    HMAC по RFC 2104 (через стандартный hmac).
    Возвращает (hex, base64|None).
    """
    # Поддержка b2b-* для HMAC недоступна напрямую — используем hashlib.new
    if _is_b2b(algo):
        # HMAC с BLAKE2b лучше заменить на blake2b с ключом (см. blake2b_keyed)
        raise ValueError("Use blake2b_keyed for keyed BLAKE2b instead of HMAC with b2b-*")

    try:
        digestmod = hashlib.new(algo)
    except Exception as e:
        raise ValueError(f"Unsupported HMAC algorithm: {algo}") from e

    hm = _hmac.new(key, data, digestmod.name)
    hexd = hm.hexdigest()
    if uppercase_hex:
        hexd = hexd.upper()
    b64d = base64.b64encode(hm.digest()).decode("ascii") if return_base64 else None
    return hexd, b64d


def blake2b_keyed(
    data: bytes,
    key: Optional[bytes] = None,
    *,
    digest_size_bits: int = 256,
    salt: Optional[bytes] = None,
    person: Optional[bytes] = None,
    return_base64: bool = False,
    uppercase_hex: bool = False,
) -> Tuple[str, Optional[str]]:
    """
    Ключевой BLAKE2b с поддержкой salt/person (см. RFC 7693).
    """
    if digest_size_bits % 8 != 0 or not (8 <= digest_size_bits <= 512):
        raise ValueError("digest_size_bits must be a multiple of 8 in [8..512]")

    h = hashlib.blake2b(
        digest_size=digest_size_bits // 8,
        key=key or b"",
        salt=salt,
        person=person,
    )
    h.update(data)
    hexd = h.hexdigest()
    if uppercase_hex:
        hexd = hexd.upper()
    b64d = base64.b64encode(h.digest()).decode("ascii") if return_base64 else None
    return hexd, b64d


def verify_digest(
    expected_hex: str,
    data: Union[bytes, str, Path],
    *,
    algo: str = _DEFAULT_ALGO,
    is_text: bool = False,
    encoding: str = "utf-8",
    normalize_newlines: bool = False,
) -> bool:
    """
    Константно‑временная проверка совпадения дайджеста.
    data: bytes | str (если is_text=True) | Path (файл)
    """
    if isinstance(data, (bytes, bytearray, memoryview)):
        res = hash_bytes(bytes(data), HashConfig(algo=algo))
        actual = res.hex
    elif isinstance(data, Path) or (isinstance(data, str) and not is_text and os.path.exists(str(data))):
        res = hash_file(str(data), HashConfig(algo=algo))
        actual = res.hex
    else:
        # трактуем как текст
        cfg = HashConfig(algo=algo, encoding=encoding, normalize_newlines=normalize_newlines)
        res = hash_text(str(data), cfg)
        actual = res.hex

    # Сравнение в константном времени
    try:
        return _hmac.compare_digest(actual.lower(), expected_hex.lower())
    except Exception:
        return False


def to_cas_uri(h: HashResult, prefix: str = "cas://", shard: int = 2) -> str:
    """
    Формирует контент‑адресный URI: cas://<algo>/<shard>/<hex>
    shard — число символов префикса для шардирования каталога.
    """
    s = max(0, min(shard, len(h.hex)))
    head = h.hex[:s]
    return f"{prefix}{h.algo}/{head}/{h.hex}"


# ---------------------------
# Вспомогательные удобства для интеграции
# ---------------------------

def hash_path_or_bytes(
    data: Union[bytes, os.PathLike, str],
    cfg: Optional[HashConfig] = None
) -> HashResult:
    """
    Унифицированный вход: если путь существует — хэшируем файл, иначе считаем это текстом.
    """
    cfg = cfg or HashConfig()
    if isinstance(data, (bytes, bytearray, memoryview)):
        return hash_bytes(bytes(data), cfg)
    p = Path(str(data))
    if p.exists() and p.is_file():
        return hash_file(p, cfg)
    return hash_text(str(data), cfg)


# ---------------------------
# Демонстратор корректности (можно вызвать вручную)
# ---------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    sample = b"DataFabric hashing module\n"
    cfg = HashConfig(algo="b2b-256", return_base64=True)

    r1 = hash_bytes(sample, cfg)
    print("hash_bytes:", r1)

    r2 = hash_text("строка\n", HashConfig(algo="sha3_256", normalize_newlines=True))
    print("hash_text:", r2)

    # Мультихэш из одного потока
    buf = io.BytesIO(sample * 1000)
    multi = multi_hash_stream(buf, ["sha256", "sha3_256", "b2b-256"])
    print("multi_hash_stream:", {k: v.hex for k, v in multi.items()})

    # HMAC
    hm_hex, hm_b64 = hmac_bytes(b"key", sample, "sha256", return_base64=True)
    print("hmac:", hm_hex, hm_b64)

    # BLAKE2b keyed
    b2_hex, _ = blake2b_keyed(sample, key=b"key", digest_size_bits=256)
    print("blake2b_keyed:", b2_hex)

    # Канонический JSON
    rj = hash_json_canonical({"b": 2, "a": [3, 1]}, HashConfig(algo="sha256"))
    print("hash_json_canonical:", rj.as_multihash())

    # CAS URI
    print("CAS:", to_cas_uri(r1))
