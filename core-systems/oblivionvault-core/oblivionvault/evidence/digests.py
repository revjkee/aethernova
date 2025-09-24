# oblivionvault-core/oblivionvault/evidence/digests.py
# Industrial-grade evidence digest utilities for OblivionVault.
# Copyright (c) 2025 NeuroCity
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import dataclasses
import functools
import hashlib
import hmac as _hmac
import io
import json
import mmap
import os
import sys
import unicodedata
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import (
    Iterable,
    Iterator,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    Union,
    Dict,
    Any,
    Set,
)

# Optional blake3 support (strongly recommended for high performance hashing)
try:
    import blake3 as _blake3  # type: ignore
except Exception:
    _blake3 = None  # gracefully degrade


__all__ = [
    "HashAlgorithm",
    "Digest",
    "DigestError",
    "FileAccessError",
    "hash_bytes",
    "hash_text",
    "hash_json",
    "hash_file",
    "hash_dir",
    "hmac_digest",
    "compare_digests_ct",
    "multihash_encode",
    "MerkleNode",
    "merkle_root",
    "DigestManifest",
    "canonical_json_dumps",
]

__version__ = "1.0.0"


# ==============================
# Exceptions
# ==============================

class DigestError(RuntimeError):
    """Errors related to digest computation."""
    pass


class FileAccessError(DigestError):
    """Errors related to file system access and traversal."""
    pass


# ==============================
# Algorithms & Registry
# ==============================

class HashAlgorithm(str, Enum):
    SHA256 = "sha256"
    SHA3_256 = "sha3_256"
    SHA512 = "sha512"
    BLAKE2B = "blake2b"
    BLAKE2S = "blake2s"
    BLAKE3 = "blake3"  # optional, requires blake3 package


# Mapping to hashlib constructors and properties
_HASHLIB_FACTORIES: Dict[HashAlgorithm, Any] = {
    HashAlgorithm.SHA256: hashlib.sha256,
    HashAlgorithm.SHA3_256: hashlib.sha3_256,
    HashAlgorithm.SHA512: hashlib.sha512,
    HashAlgorithm.BLAKE2B: hashlib.blake2b,
    HashAlgorithm.BLAKE2S: hashlib.blake2s,
}

# Multihash codes (subset) — https://multiformats.io/multihash/
# Only the subset we support; extend as needed.
_MULTIHASH_CODES: Dict[HashAlgorithm, int] = {
    HashAlgorithm.SHA256: 0x12,     # sha2-256
    HashAlgorithm.SHA3_256: 0x16,   # sha3-256
    HashAlgorithm.SHA512: 0x13,     # sha2-512
    HashAlgorithm.BLAKE2B: 0xb220,  # blake2b-256 (we encode 32-byte digests)
    HashAlgorithm.BLAKE2S: 0xb250,  # blake2s-256 (32-byte)
    # Blake3 256-bit is not standardized in classic multihash table; use unofficial code if needed.
}

# Default digest sizes for BLAKE2 variants when unspecified
_B2B_DEFAULT_DIGEST_SIZE = 32
_B2S_DEFAULT_DIGEST_SIZE = 32

# Chunk size for streaming reads
_DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB

# Threshold for using mmap
_DEFAULT_MMAP_THRESHOLD = 8 * 1024 * 1024  # 8 MiB

# Domain separation bytes for Merkle hashing
_DS_LEAF = b"\x00"
_DS_NODE = b"\x01"
_DS_PATHSEP = b"/"


@dataclass(frozen=True)
class Digest:
    """Digest value with metadata."""
    algorithm: HashAlgorithm
    raw: bytes

    def hex(self) -> str:
        return self.raw.hex()

    def b64(self, urlsafe: bool = True, strip_padding: bool = False) -> str:
        b = base64.urlsafe_b64encode(self.raw) if urlsafe else base64.b64encode(self.raw)
        s = b.decode("ascii")
        return s.rstrip("=") if strip_padding else s

    def __str__(self) -> str:
        return f"{self.algorithm}:{self.hex()}"

    def __len__(self) -> int:
        return len(self.raw)


# ==============================
# Normalization & Canonicalization
# ==============================

def _normalize_text(
    text: str,
    *,
    newline_lf: bool = True,
    unicode_nfkc: bool = True,
    strip_bom: bool = True,
) -> str:
    # Strip UTF-8 BOM if present
    if strip_bom and text.startswith("\ufeff"):
        text = text.lstrip("\ufeff")
    if newline_lf:
        text = text.replace("\r\n", "\n").replace("\r", "\n")
    if unicode_nfkc:
        text = unicodedata.normalize("NFKC", text)
    return text


def canonical_json_dumps(
    obj: Any,
    *,
    ensure_ascii: bool = False,
) -> str:
    """
    Deterministic JSON suitable for stable hashing:
    - Sort keys
    - No spaces (',' ':')
    - UTF-8 by default
    Note: Not a full RFC 8785 implementation, but deterministic for typical data.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=ensure_ascii,
        allow_nan=False,
    )


# ==============================
# Hash Primitives
# ==============================

def _new_hasher(algo: HashAlgorithm, *, digest_size: Optional[int] = None):
    if algo == HashAlgorithm.BLAKE3:
        if _blake3 is None:
            raise DigestError(
                "Algorithm blake3 requested but 'blake3' package is not available. "
                "Install with: pip install blake3"
            )
        return _blake3.blake3() if digest_size is None else _blake3.blake3(max_threads=0)  # digest size at finalize
    if algo in (HashAlgorithm.BLAKE2B, HashAlgorithm.BLAKE2S):
        if digest_size is None:
            if algo == HashAlgorithm.BLAKE2B:
                digest_size = _B2B_DEFAULT_DIGEST_SIZE
            else:
                digest_size = _B2S_DEFAULT_DIGEST_SIZE
        return _HASHLIB_FACTORIES[algo](digest_size=digest_size)
    factory = _HASHLIB_FACTORIES.get(algo)
    if factory is None:
        raise DigestError(f"Unsupported algorithm: {algo}")
    return factory()


def _finalize_hasher(algo: HashAlgorithm, hasher, *, digest_size: Optional[int] = None) -> bytes:
    if algo == HashAlgorithm.BLAKE3:
        if digest_size is None:
            digest_size = 32
        return hasher.digest(length=digest_size)
    return hasher.digest()


def hash_bytes(
    data: bytes,
    *,
    algorithm: HashAlgorithm = HashAlgorithm.SHA256,
    blake2_digest_size: Optional[int] = None,
) -> Digest:
    hasher = _new_hasher(algorithm, digest_size=blake2_digest_size)
    hasher.update(data)
    raw = _finalize_hasher(algorithm, hasher, digest_size=blake2_digest_size)
    return Digest(algorithm, raw)


def hash_text(
    text: str,
    *,
    algorithm: HashAlgorithm = HashAlgorithm.SHA256,
    encoding: str = "utf-8",
    normalize_newlines: bool = True,
    unicode_nfkc: bool = True,
    strip_bom: bool = True,
    blake2_digest_size: Optional[int] = None,
) -> Digest:
    text = _normalize_text(
        text,
        newline_lf=normalize_newlines,
        unicode_nfkc=unicode_nfkc,
        strip_bom=strip_bom,
    )
    data = text.encode(encoding)
    return hash_bytes(data, algorithm=algorithm, blake2_digest_size=blake2_digest_size)


def hash_json(
    obj: Any,
    *,
    algorithm: HashAlgorithm = HashAlgorithm.SHA256,
    ensure_ascii: bool = False,
    blake2_digest_size: Optional[int] = None,
) -> Digest:
    s = canonical_json_dumps(obj, ensure_ascii=ensure_ascii)
    return hash_text(
        s,
        algorithm=algorithm,
        normalize_newlines=True,
        unicode_nfkc=False,  # JSON already in ASCII/UTF-8 canonical form here
        strip_bom=True,
        blake2_digest_size=blake2_digest_size,
    )


def hmac_digest(
    key: Union[bytes, str],
    data: Union[bytes, str],
    *,
    algorithm: HashAlgorithm = HashAlgorithm.SHA256,
    encoding: str = "utf-8",
) -> Digest:
    if isinstance(key, str):
        key = key.encode(encoding)
    if isinstance(data, str):
        data = data.encode(encoding)
    if algorithm == HashAlgorithm.BLAKE3:
        # blake3 keyed hashing (KDF) differs from HMAC; avoid misusing here
        raise DigestError("Use blake3 keyed mode separately; HMAC is for hashlib algorithms.")
    factory = _HASHLIB_FACTORIES.get(algorithm)
    if not factory:
        raise DigestError(f"HMAC unsupported algorithm: {algorithm}")
    mac = _hmac.new(key, data, digestmod=factory)
    return Digest(algorithm, mac.digest())


def compare_digests_ct(a: Union[Digest, bytes], b: Union[Digest, bytes]) -> bool:
    a_raw = a.raw if isinstance(a, Digest) else a
    b_raw = b.raw if isinstance(b, Digest) else b
    return _hmac.compare_digest(a_raw, b_raw)


# ==============================
# File & Directory Hashing
# ==============================

def _should_use_mmap(size: int, threshold: int) -> bool:
    return size >= threshold and size > 0


def _open_file_for_hash(path: Path) -> Tuple[io.BufferedReader, int]:
    try:
        f = open(path, "rb", buffering=0)
    except OSError as e:
        raise FileAccessError(f"Cannot open file for reading: {path!s} -> {e}") from e
    try:
        st = os.fstat(f.fileno())
        size = st.st_size
    except OSError as e:
        f.close()
        raise FileAccessError(f"Cannot stat file: {path!s} -> {e}") from e
    return f, size


def hash_file(
    path: Union[str, Path],
    *,
    algorithm: HashAlgorithm = HashAlgorithm.SHA256,
    chunk_size: int = _DEFAULT_CHUNK_SIZE,
    mmap_threshold: int = _DEFAULT_MMAP_THRESHOLD,
    follow_symlinks: bool = False,
    blake2_digest_size: Optional[int] = None,
) -> Digest:
    p = Path(path)
    if not follow_symlinks and p.is_symlink():
        raise FileAccessError(f"Symlink hashing disabled: {p!s}")
    if not p.exists():
        raise FileAccessError(f"File does not exist: {p!s}")
    if not p.is_file():
        raise FileAccessError(f"Not a regular file: {p!s}")

    hasher = _new_hasher(algorithm, digest_size=blake2_digest_size)

    f, size = _open_file_for_hash(p)
    try:
        if _should_use_mmap(size, mmap_threshold):
            try:
                with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
                    # Feed in large slices to avoid Python-level loop overhead
                    view = memoryview(mm)
                    hasher.update(view)
            except (BufferError, ValueError, OSError):
                # Fall back to streaming if mmap unsupported
                _stream_hash_read(f, hasher, chunk_size)
        else:
            _stream_hash_read(f, hasher, chunk_size)
    finally:
        f.close()

    raw = _finalize_hasher(algorithm, hasher, digest_size=blake2_digest_size)
    return Digest(algorithm, raw)


def _stream_hash_read(fh: io.BufferedReader, hasher, chunk_size: int) -> None:
    while True:
        chunk = fh.read(chunk_size)
        if not chunk:
            break
        hasher.update(chunk)


def _canonical_rel_path(root: Path, file: Path) -> str:
    rel = file.relative_to(root)
    # Use POSIX-style separators for stability
    parts = []
    for part in rel.parts:
        # Normalize path component unicode for determinism
        parts.append(unicodedata.normalize("NFKC", part))
    return "/".join(parts)


@dataclass(frozen=True)
class MerkleNode:
    left: Optional["MerkleNode"]
    right: Optional["MerkleNode"]
    digest: Digest
    is_leaf: bool = False
    label: Optional[str] = None  # for leaves: canonical relative path


def _hash_leaf(
    path_label: str,
    file_digest: Digest,
    *,
    algorithm: HashAlgorithm,
) -> Digest:
    # Domain separated leaf hash: H( 0x00 || path || 0x2f || file_digest )
    h = _new_hasher(algorithm)
    h.update(_DS_LEAF)
    h.update(path_label.encode("utf-8"))
    h.update(_DS_PATHSEP)
    h.update(file_digest.raw)
    return Digest(algorithm, _finalize_hasher(algorithm, h))


def _hash_node(
    left: Digest,
    right: Digest,
    *,
    algorithm: HashAlgorithm,
) -> Digest:
    # Domain separated inner node: H( 0x01 || left || right )
    h = _new_hasher(algorithm)
    h.update(_DS_NODE)
    h.update(left.raw)
    h.update(right.raw)
    return Digest(algorithm, _finalize_hasher(algorithm, h))


def merkle_root(
    leaves: Sequence[Digest],
    *,
    algorithm: HashAlgorithm = HashAlgorithm.SHA256,
) -> Digest:
    if not leaves:
        # Hash of empty list is defined deterministically
        return hash_bytes(b"", algorithm=algorithm)
    level = list(leaves)
    while len(level) > 1:
        nxt: List[Digest] = []
        it = iter(level)
        for a in it:
            try:
                b = next(it)
            except StopIteration:
                # Duplicate last if odd number of leaves
                b = a
            nxt.append(_hash_node(a, b, algorithm=algorithm))
        level = nxt
    return level[0]


@dataclass
class DigestManifest:
    """
    Manifest of files -> digests with Merkle root for a directory tree.
    """
    algorithm: HashAlgorithm
    root: Digest
    files: Dict[str, str]  # rel_path -> hex digest (leaf/file digest, not leaf-hash)
    leaf_hashes: Dict[str, str]  # rel_path -> hex (domain-separated leaf hash)

    def to_json(self) -> str:
        payload = {
            "algorithm": self.algorithm.value,
            "root": self.root.hex(),
            "files": self.files,
            "leaf_hashes": self.leaf_hashes,
        }
        return canonical_json_dumps(payload, ensure_ascii=False)

    def to_bytes(self) -> bytes:
        return self.to_json().encode("utf-8")


def hash_dir(
    path: Union[str, Path],
    *,
    algorithm: HashAlgorithm = HashAlgorithm.SHA256,
    include: Optional[Sequence[str]] = None,
    exclude: Optional[Sequence[str]] = None,
    follow_symlinks: bool = False,
    chunk_size: int = _DEFAULT_CHUNK_SIZE,
    mmap_threshold: int = _DEFAULT_MMAP_THRESHOLD,
    blake2_digest_size: Optional[int] = None,
) -> Tuple[Digest, DigestManifest]:
    """
    Hash a directory deterministically:
    - Walks files in lexicographic order by canonical POSIX-style relative path
    - Applies include / exclude glob filters
    - Excludes symlinks by default
    - Uses domain separated leaf hashes for Merkle tree
    Returns (root_digest, manifest)
    """
    root = Path(path).resolve()
    if not root.exists():
        raise FileAccessError(f"Directory does not exist: {root!s}")
    if not root.is_dir():
        raise FileAccessError(f"Not a directory: {root!s}")

    include = list(include) if include else ["**/*"]
    exclude_patterns = list(exclude) if exclude else []

    files: List[Path] = []
    for inc in include:
        files.extend(root.glob(inc))
    # keep regular files only
    files = [f for f in files if f.is_file()]
    # apply exclusion
    if exclude_patterns:
        excluded: Set[Path] = set()
        for ex in exclude_patterns:
            excluded.update(root.glob(ex))
        files = [f for f in files if f not in excluded]

    # Deduplicate and order deterministically by canonical rel path
    rel_pairs: List[Tuple[str, Path]] = []
    seen: Set[str] = set()
    for f in files:
        if f.is_symlink() and not follow_symlinks:
            continue
        try:
            rel = _canonical_rel_path(root, f)
        except ValueError:
            # File outside root? Skip safely
            continue
        if rel in seen:
            continue
        seen.add(rel)
        rel_pairs.append((rel, f))

    rel_pairs.sort(key=lambda x: x[0])

    # Compute file digests
    file_digests: Dict[str, Digest] = {}
    leaf_digests: Dict[str, Digest] = {}
    leaf_list: List[Digest] = []

    for rel, fpath in rel_pairs:
        d = hash_file(
            fpath,
            algorithm=algorithm,
            chunk_size=chunk_size,
            mmap_threshold=mmap_threshold,
            follow_symlinks=follow_symlinks,
            blake2_digest_size=blake2_digest_size,
        )
        file_digests[rel] = d
        leaf = _hash_leaf(rel, d, algorithm=algorithm)
        leaf_digests[rel] = leaf
        leaf_list.append(leaf)

    root_digest = merkle_root(leaf_list, algorithm=algorithm)

    manifest = DigestManifest(
        algorithm=algorithm,
        root=root_digest,
        files={k: v.hex() for k, v in file_digests.items()},
        leaf_hashes={k: v.hex() for k, v in leaf_digests.items()},
    )
    return root_digest, manifest


# ==============================
# Multihash encoding
# ==============================

def _varint_encode(n: int) -> bytes:
    out = bytearray()
    while True:
        to_write = n & 0x7F
        n >>= 7
        if n:
            out.append(to_write | 0x80)
        else:
            out.append(to_write)
            break
    return bytes(out)


def multihash_encode(digest: Digest) -> bytes:
    """
    Minimal multihash encoder for supported algorithms.
    Encodes: <varint code><varint length><digest bytes>
    """
    code = _MULTIHASH_CODES.get(digest.algorithm)
    if code is None:
        raise DigestError(f"Multihash not supported for algorithm: {digest.algorithm.value}")
    length = len(digest.raw)
    return _varint_encode(code) + _varint_encode(length) + digest.raw


# ==============================
# CLI
# ==============================

def _parse_args(argv: Sequence[str]) -> Tuple[str, Dict[str, Any]]:
    import argparse

    parser = argparse.ArgumentParser(
        prog="oblivionvault-digests",
        description="Compute evidence digests and Merkle roots.",
    )
    parser.add_argument("target", help="File or directory path.")
    parser.add_argument(
        "--algo",
        dest="algo",
        default=HashAlgorithm.SHA256.value,
        choices=[a.value for a in HashAlgorithm],
        help="Hash algorithm.",
    )
    parser.add_argument("--dir", action="store_true", help="Treat target as directory.")
    parser.add_argument("--include", action="append", default=[], help="Glob include (repeatable). Default **/*")
    parser.add_argument("--exclude", action="append", default=[], help="Glob exclude (repeatable).")
    parser.add_argument("--chunk", type=int, default=_DEFAULT_CHUNK_SIZE, help="Stream chunk size in bytes.")
    parser.add_argument("--mmap", type=int, default=_DEFAULT_MMAP_THRESHOLD, help="mmap threshold in bytes.")
    parser.add_argument("--follow-symlinks", action="store_true", help="Follow symlinks.")
    parser.add_argument("--manifest", type=str, default="", help="Write manifest JSON to this path (for dirs).")
    parser.add_argument("--b64", action="store_true", help="Output base64 (URL-safe) instead of hex.")
    parser.add_argument("--multihash", action="store_true", help="Output multihash (base64url).")
    parser.add_argument("--json", action="store_true", help="Emit JSON object with fields.")

    args = parser.parse_args(argv)

    algo = HashAlgorithm(args.algo)
    opts: Dict[str, Any] = dict(
        algorithm=algo,
        include=args.include or None,
        exclude=args.exclude or None,
        chunk_size=args.chunk,
        mmap_threshold=args.mmap,
        follow_symlinks=args.follow_symlinks,
        output_b64=args.b64,
        output_multihash=args.multihash,
        emit_json=args.json,
        manifest_path=args.manifest or None,
        is_dir=args.dir,
    )
    return args.target, opts


def _cli_print_digest(d: Digest, *, b64: bool, multihash_b64: bool, as_json: bool) -> None:
    if as_json:
        out = {
            "algorithm": d.algorithm.value,
            "hex": d.hex(),
            "b64url": d.b64(urlsafe=True, strip_padding=False),
        }
        try:
            mh = multihash_encode(d)
            out["multihash_b64url"] = base64.urlsafe_b64encode(mh).decode("ascii")
        except DigestError:
            pass
        print(canonical_json_dumps(out, ensure_ascii=False))
        return

    if multihash_b64:
        mh = multihash_encode(d)
        print(base64.urlsafe_b64encode(mh).decode("ascii"))
        return

    if b64:
        print(d.b64(urlsafe=True))
    else:
        print(d.hex())


def _cli(argv: Sequence[str]) -> int:
    target, opts = _parse_args(argv)
    algo: HashAlgorithm = opts["algorithm"]
    is_dir: bool = opts["is_dir"]
    b64: bool = opts["output_b64"]
    mh: bool = opts["output_multihash"]
    as_json: bool = opts["emit_json"]
    manifest_path: Optional[str] = opts["manifest_path"]

    try:
        p = Path(target)
        if is_dir or p.is_dir():
            root, manifest = hash_dir(
                p,
                algorithm=algo,
                include=opts["include"],
                exclude=opts["exclude"],
                follow_symlinks=opts["follow_symlinks"],
                chunk_size=opts["chunk_size"],
                mmap_threshold=opts["mmap_threshold"],
            )
            if manifest_path:
                Path(manifest_path).write_text(manifest.to_json(), encoding="utf-8")
            _cli_print_digest(root, b64=b64, multihash_b64=mh, as_json=as_json)
        else:
            d = hash_file(
                p,
                algorithm=algo,
                chunk_size=opts["chunk_size"],
                mmap_threshold=opts["mmap_threshold"],
                follow_symlinks=opts["follow_symlinks"],
            )
            _cli_print_digest(d, b64=b64, multihash_b64=mh, as_json=as_json)
    except (DigestError, FileAccessError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
