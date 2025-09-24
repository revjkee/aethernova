# -*- coding: utf-8 -*-
"""
DataFabric | utils | hashing.py

Единый промышленный слой хэш‑утилит для всего проекта.
Если доступен модуль datafabric.processing.transforms.hashing — реэкспорт его API.
Иначе: автономная реализация без внешних зависимостей.

Особенности (fallback-реализация):
- Алгоритмы: sha256, sha512, sha3_256, sha3_512, b2b-N (BLAKE2b N∈{8..512} бит)
- Стриминговое хэширование: bytes / поток / файл (mmap + fallback)
- Мультихэш (несколько алгоритмов за один проход)
- HMAC (RFC 2104) и BLAKE2b keyed (RFC 7693)
- Канонический JSON‑хэш (детерминированная сериализация)
- CAS URI: cas://<algo>/<prefix>/<hex>
- Верификация в константном времени
- Merkle‑хэширование директорий/наборов (дерево и корневой дайджест)
"""

from __future__ import annotations

# Попытка использовать промышленную версию из processing/transforms
try:  # pragma: no cover
    from datafabric.processing.transforms.hashing import (  # type: ignore
        HashConfig,
        HashResult,
        SUPPORTED_ALGOS,
        hash_bytes,
        hash_text,
        hash_stream,
        hash_file,
        hash_json_canonical,
        multi_hash_stream,
        hmac_bytes,
        blake2b_keyed,
        verify_digest,
        to_cas_uri,
        hash_path_or_bytes,
    )
    # Дополнительно предоставим Merkle‑утилиты поверх базовых функций:
    import dataclasses
    import hashlib as _hashlib
    import io
    import json
    import os
    from dataclasses import dataclass
    from pathlib import Path
    from typing import BinaryIO, Dict, Iterable, Iterator, List, Mapping, Optional, Tuple, Union

    _DEFAULT_CHUNK = 1024 * 1024

    @dataclass(frozen=True)
    class MerkleNode:
        """
        Узел Merkle‑дерева (по файлам). Хэш узла = H(type|name|size|children_hashes|file_hash)
        """
        name: str
        is_dir: bool
        size: int
        digest_hex: str
        children: Tuple["MerkleNode", ...] = ()

    def _canon_name(p: Path) -> str:
        # Канонизированное относительное имя с '/' как разделителем
        return "/".join(p.parts)

    def merkle_from_directory(
        root_dir: Union[str, Path],
        *,
        algo: str = "b2b-256",
        include_hidden: bool = False,
        follow_symlinks: bool = False,
    ) -> MerkleNode:
        """
        Строит Merkle‑дерево для каталога. Порядок детей лексикографический по имени.
        """
        root = Path(root_dir).resolve()
        if not root.exists():
            raise FileNotFoundError(root)

        def walk(dir_path: Path, rel: Path) -> MerkleNode:
            items: List[MerkleNode] = []
            for entry in sorted(dir_path.iterdir(), key=lambda p: p.name):
                if not include_hidden and entry.name.startswith("."):
                    continue
                if entry.is_symlink() and not follow_symlinks:
                    continue
                rel_child = rel / entry.name
                if entry.is_dir():
                    node = walk(entry, rel_child)
                    items.append(node)
                elif entry.is_file():
                    hres = hash_file(entry, HashConfig(algo=algo))
                    node = MerkleNode(
                        name=_canon_name(rel_child),
                        is_dir=False,
                        size=entry.stat().st_size,
                        digest_hex=hres.hex,
                        children=(),
                    )
                    items.append(node)
                # иные типы игнорируем
            # Хэш директории — хэш конкатенации детских записей в каноническом JSON
            meta = {
                "type": "dir",
                "name": _canon_name(rel),
                "children": [
                    {"name": n.name, "is_dir": n.is_dir, "size": n.size, "digest": n.digest_hex}
                    for n in items
                ],
            }
            dh = hash_json_canonical(meta, HashConfig(algo=algo)).hex
            size = sum(n.size for n in items)
            return MerkleNode(name=_canon_name(rel), is_dir=True, size=size, digest_hex=dh, children=tuple(items))

        return walk(root, Path("."))

    def merkle_root_hex(root_dir: Union[str, Path], *, algo: str = "b2b-256") -> str:
        return merkle_from_directory(root_dir, algo=algo).digest_hex

except Exception:
    # ------------------------------
    # Автономная реализация (fallback)
    # ------------------------------
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
        "hash_path_or_bytes",
        "MerkleNode",
        "merkle_from_directory",
        "merkle_root_hex",
    ]

    # ---------------------------
    # Константы
    # ---------------------------
    SUPPORTED_ALGOS: Mapping[str, str] = {
        "sha256": "sha256",
        "sha512": "sha512",
        "sha3_256": "sha3_256",
        "sha3_512": "sha3_512",
    }
    _DEFAULT_CHUNK = 1024 * 1024
    _MIN_CHUNK = 64 * 1024
    _MAX_CHUNK = 32 * 1024 * 1024
    _MMAP_THRESHOLD = 8 * 1024 * 1024
    _DEFAULT_ALGO = "b2b-256"

    # ---------------------------
    # Структуры данных
    # ---------------------------
    @dataclass(frozen=True)
    class HashConfig:
        algo: str = _DEFAULT_ALGO
        chunk_size: int = _DEFAULT_CHUNK
        encoding: str = "utf-8"
        normalize_newlines: bool = False
        return_base64: bool = False
        uppercase_hex: bool = False

        def normalized_chunk(self) -> int:
            return max(_MIN_CHUNK, min(self.chunk_size, _MAX_CHUNK))

    @dataclass(frozen=True)
    class HashResult:
        algo: str
        hex: str
        b64: Optional[str]
        size_bytes: Optional[int]
        digest_size_bits: int

        def as_multihash(self) -> str:
            return f"{self.algo}:{self.hex}"

    # ---------------------------
    # Внутренние помощники
    # ---------------------------
    def _is_b2b(algo: str) -> bool:
        return algo.startswith("b2b-") and algo[4:].isdigit()

    def _b2b_digest_size_from_algo(algo: str) -> int:
        bits = int(algo.split("-", 1)[1])
        if bits % 8 != 0 or not (8 <= bits <= 512):
            raise ValueError(f"Unsupported BLAKE2b digest size: {bits}")
        return bits // 8

    def _new_hasher(algo: str) -> "hashlib._Hash":
        if _is_b2b(algo):
            return hashlib.blake2b(digest_size=_b2b_digest_size_from_algo(algo))
        if algo in SUPPORTED_ALGOS:
            return hashlib.new(SUPPORTED_ALGOS[algo])
        # попытка через hashlib.new для расширенных алгоритмов OpenSSL
        return hashlib.new(algo)

    def _digest_size_bits(algo: str, h: "hashlib._Hash") -> int:
        return (_b2b_digest_size_from_algo(algo) * 8) if _is_b2b(algo) else h.digest_size * 8

    def _maybe_normalize_text(s: str, normalize: bool) -> str:
        return s.replace("\r\n", "\n").replace("\r", "\n") if normalize else s

    def _to_result(algo: str, h: "hashlib._Hash", size_bytes: Optional[int], cfg: HashConfig) -> HashResult:
        hexd = h.hexdigest()
        if cfg.uppercase_hex:
            hexd = hexd.upper()
        b64d = base64.b64encode(h.digest()).decode("ascii") if cfg.return_base64 else None
        return HashResult(algo=algo, hex=hexd, b64=b64d, size_bytes=size_bytes, digest_size_bits=_digest_size_bits(algo, h))

    # ---------------------------
    # Публичные хэши
    # ---------------------------
    def hash_bytes(data: bytes, cfg: Optional[HashConfig] = None) -> HashResult:
        cfg = cfg or HashConfig()
        h = _new_hasher(cfg.algo)
        h.update(data)
        return _to_result(cfg.algo, h, len(data), cfg)

    def hash_text(text: str, cfg: Optional[HashConfig] = None) -> HashResult:
        cfg = cfg or HashConfig()
        s = _maybe_normalize_text(text, cfg.normalize_newlines)
        return hash_bytes(s.encode(cfg.encoding), cfg)

    def hash_stream(stream: BinaryIO, cfg: Optional[HashConfig] = None) -> HashResult:
        cfg = cfg or HashConfig()
        h = _new_hasher(cfg.algo)
        total = 0
        chunk = stream.read(cfg.normalized_chunk())
        while chunk:
            h.update(chunk)
            total += len(chunk)
            chunk = stream.read(cfg.normalized_chunk())
        return _to_result(cfg.algo, h, total, cfg)

    def _replace_size(self: HashResult, size: int) -> HashResult:
        return dataclasses.replace(self, size_bytes=size)

    setattr(HashResult, "_replace_size", _replace_size)

    def hash_file(path: Union[str, os.PathLike], cfg: Optional[HashConfig] = None) -> HashResult:
        cfg = cfg or HashConfig()
        p = Path(path)
        size = p.stat().st_size
        h = _new_hasher(cfg.algo)
        if size >= _MMAP_THRESHOLD:
            with p.open("rb") as f:
                try:
                    with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
                        h.update(memoryview(mm))
                except (BufferError, ValueError, OSError):
                    f.seek(0)
                    return hash_stream(f, cfg)._replace_size(size)
        else:
            with p.open("rb") as f:
                return hash_stream(f, cfg)._replace_size(size)
        return _to_result(cfg.algo, h, size, cfg)

    def hash_json_canonical(obj: object, cfg: Optional[HashConfig] = None) -> HashResult:
        cfg = cfg or HashConfig()
        data = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(cfg.encoding)
        return hash_bytes(data, cfg)

    def multi_hash_stream(stream: BinaryIO, algos: List[str], chunk_size: int = _DEFAULT_CHUNK) -> Dict[str, HashResult]:
        if not algos:
            raise ValueError("algos must not be empty")
        normalized = max(_MIN_CHUNK, min(chunk_size, _MAX_CHUNK))
        hashers: Dict[str, "hashlib._Hash"] = {a: _new_hasher(a) for a in algos}
        total = 0
        chunk = stream.read(normalized)
        while chunk:
            for h in hashers.values():
                h.update(chunk)
            total += len(chunk)
            chunk = stream.read(normalized)
        out: Dict[str, HashResult] = {}
        for a, h in hashers.items():
            out[a] = HashResult(algo=a, hex=h.hexdigest(), b64=None, size_bytes=total, digest_size_bits=_digest_size_bits(a, h))
        return out

    def hmac_bytes(key: bytes, data: bytes, algo: str = "sha256", return_base64: bool = False, uppercase_hex: bool = False) -> Tuple[str, Optional[str]]:
        if _is_b2b(algo):
            raise ValueError("Use blake2b_keyed for keyed BLAKE2b")
        try:
            dm = hashlib.new(algo)
        except Exception as e:
            raise ValueError(f"Unsupported HMAC algorithm: {algo}") from e
        hm = _hmac.new(key, data, dm.name)
        hexd = hm.hexdigest().upper() if uppercase_hex else hm.hexdigest()
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
        if digest_size_bits % 8 != 0 or not (8 <= digest_size_bits <= 512):
            raise ValueError("digest_size_bits must be multiple of 8 in [8..512]")
        h = hashlib.blake2b(digest_size=digest_size_bits // 8, key=key or b"", salt=salt, person=person)
        h.update(data)
        hexd = h.hexdigest().upper() if uppercase_hex else h.hexdigest()
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
        if isinstance(data, (bytes, bytearray, memoryview)):
            res = hash_bytes(bytes(data), HashConfig(algo=algo))
            actual = res.hex
        elif isinstance(data, Path) or (isinstance(data, str) and not is_text and os.path.exists(str(data))):
            res = hash_file(str(data), HashConfig(algo=algo))
            actual = res.hex
        else:
            cfg = HashConfig(algo=algo, encoding=encoding, normalize_newlines=normalize_newlines)
            res = hash_text(str(data), cfg)
            actual = res.hex
        try:
            return _hmac.compare_digest(actual.lower(), expected_hex.lower())
        except Exception:
            return False

    def to_cas_uri(h: HashResult, prefix: str = "cas://", shard: int = 2) -> str:
        s = max(0, min(shard, len(h.hex)))
        head = h.hex[:s]
        return f"{prefix}{h.algo}/{head}/{h.hex}"

    def hash_path_or_bytes(data: Union[bytes, os.PathLike, str], cfg: Optional[HashConfig] = None) -> HashResult:
        cfg = cfg or HashConfig()
        if isinstance(data, (bytes, bytearray, memoryview)):
            return hash_bytes(bytes(data), cfg)
        p = Path(str(data))
        if p.exists() and p.is_file():
            return hash_file(p, cfg)
        return hash_text(str(data), cfg)

    # ---------- Merkle ----------
    @dataclass(frozen=True)
    class MerkleNode:
        name: str
        is_dir: bool
        size: int
        digest_hex: str
        children: Tuple["MerkleNode", ...] = ()

    def _canon_name(p: Path) -> str:
        return "/".join(p.parts)

    def merkle_from_directory(
        root_dir: Union[str, Path],
        *,
        algo: str = "b2b-256",
        include_hidden: bool = False,
        follow_symlinks: bool = False,
    ) -> MerkleNode:
        root = Path(root_dir).resolve()
        if not root.exists():
            raise FileNotFoundError(root)

        def walk(dir_path: Path, rel: Path) -> MerkleNode:
            items: List[MerkleNode] = []
            for entry in sorted(dir_path.iterdir(), key=lambda p: p.name):
                if not include_hidden and entry.name.startswith("."):
                    continue
                if entry.is_symlink() and not follow_symlinks:
                    continue
                rel_child = rel / entry.name
                if entry.is_dir():
                    items.append(walk(entry, rel_child))
                elif entry.is_file():
                    hres = hash_file(entry, HashConfig(algo=algo))
                    items.append(MerkleNode(name=_canon_name(rel_child), is_dir=False, size=entry.stat().st_size, digest_hex=hres.hex))
            meta = {
                "type": "dir",
                "name": _canon_name(rel),
                "children": [
                    {"name": n.name, "is_dir": n.is_dir, "size": n.size, "digest": n.digest_hex}
                    for n in items
                ],
            }
            dh = hash_json_canonical(meta, HashConfig(algo=algo)).hex
            size = sum(n.size for n in items)
            return MerkleNode(name=_canon_name(rel), is_dir=True, size=size, digest_hex=dh, children=tuple(items))

        return walk(root, Path("."))

    def merkle_root_hex(root_dir: Union[str, Path], *, algo: str = "b2b-256") -> str:
        return merkle_from_directory(root_dir, algo=algo).digest_hex
