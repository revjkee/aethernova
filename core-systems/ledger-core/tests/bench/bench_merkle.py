# -*- coding: utf-8 -*-
"""
Industrial-grade Merkle benchmarks and correctness checks.

Usage:
  1) As pytest tests:
       pytest -q tests/bench/bench_merkle.py
     Works with or without pytest-benchmark plugin.
     If plugin is present, it will record proper benchmark stats.
     Without plugin, timing and memory stats are printed to stdout.

  2) As CLI:
       python tests/bench/bench_merkle.py --algo sha256 --leaves 16384 --leaf-size 1024 --prehash
       python tests/bench/bench_merkle.py --matrix

Features:
  - Reference Merkle implementation (binary tree, duplicate-last padding).
  - Hash algorithms: sha256, blake2b-256 (selectable).
  - Deterministic data generation.
  - Benchmarks: build_root, build_with_prehash, make_proof, verify_proof.
  - Memory peak via tracemalloc.
  - Throughput metrics (MiB/s, leaves/s).
  - Pytest integration with graceful fallback if pytest-benchmark is absent.
  - Robust correctness assertions.

Environment:
  - Python 3.9+
  - No external dependencies required.

Author: Aethernova / NeuroCity
"""

from __future__ import annotations

import argparse
import hashlib
import math
import os
import sys
import time
import tracemalloc
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional, Sequence, Tuple


# ---------------------------
# Hash selection and adapters
# ---------------------------

def _sha256(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()

def _blake2b_256(x: bytes) -> bytes:
    h = hashlib.blake2b(x, digest_size=32)
    return h.digest()

_HASHES = {
    "sha256": _sha256,
    "blake2b": _blake2b_256,
    "blake2b-256": _blake2b_256,
}

def resolve_hash(name: str) -> Callable[[bytes], bytes]:
    key = name.lower().strip()
    if key not in _HASHES:
        raise ValueError(f"Unsupported hash: {name}. Available: {sorted(_HASHES.keys())}")
    return _HASHES[key]


# ---------------------------
# Deterministic data factory
# ---------------------------

def deterministic_bytes(count: int, size: int, seed: int = 1337) -> List[bytes]:
    """
    Produce 'count' byte blobs of length 'size' deterministically from a simple
    XOF-like expansion using BLAKE2b keyed by (seed, index).
    """
    out: List[bytes] = []
    key = seed.to_bytes(16, "big", signed=False)
    for i in range(count):
        ctr = i.to_bytes(16, "big", signed=False)
        # Derive a stream using BLAKE2b and slice to size
        stream = hashlib.blake2b(key + ctr, digest_size=max(size, 32)).digest()
        if size <= len(stream):
            out.append(stream[:size])
        else:
            # For very large sizes, extend by repeated hashing
            chunks = [stream]
            while sum(len(c) for c in chunks) < size:
                stream = hashlib.blake2b(stream, digest_size=64).digest()
                chunks.append(stream)
            blob = b"".join(chunks)[:size]
            out.append(blob)
    return out


# ---------------------------
# Merkle implementation (binary)
# ---------------------------

@dataclass(frozen=True)
class MerkleParams:
    hash_fn: Callable[[bytes], bytes]
    sorted_pairs: bool = False  # If True, pair hashes are lexicographically sorted before concatenation (Bitcoin-like)


def _pair_combine(left: bytes, right: bytes, params: MerkleParams) -> bytes:
    if params.sorted_pairs and right < left:
        left, right = right, left
    return params.hash_fn(left + right)


def _next_pow2(n: int) -> int:
    return 1 if n <= 1 else 1 << (n - 1).bit_length()


def merkle_root_from_leaves(leaves: Sequence[bytes], params: MerkleParams) -> bytes:
    """
    Compute Merkle root from raw leaf blobs (hashing leaves at level 0).
    """
    if not leaves:
        return params.hash_fn(b"")
    # Hash leaves first
    level: List[bytes] = [params.hash_fn(x) for x in leaves]
    return merkle_root_from_hashed(level, params)


def merkle_root_from_hashed(hashed_leaves: Sequence[bytes], params: MerkleParams) -> bytes:
    """
    Compute Merkle root from pre-hashed leaves.
    Pads last hash if odd number of nodes at any level.
    """
    n = len(hashed_leaves)
    if n == 0:
        return params.hash_fn(b"")
    level = list(hashed_leaves)

    # If not power of two, duplicate-last padding per level is acceptable/standard in many variants.
    while len(level) > 1:
        nxt: List[bytes] = []
        it = iter(level)
        for left in it:
            try:
                right = next(it)
            except StopIteration:
                right = left
            nxt.append(_pair_combine(left, right, params))
        level = nxt
    return level[0]


def merkle_proof(hashed_leaves: Sequence[bytes], index: int, params: MerkleParams) -> List[Tuple[bytes, bool]]:
    """
    Generate Merkle proof for a pre-hashed leaf at position 'index'.
    Returns list of (sibling_hash, is_right_sibling), bottom-up.
    """
    n = len(hashed_leaves)
    if not (0 <= index < n):
        raise IndexError("Leaf index out of range")
    level = list(hashed_leaves)
    proof: List[Tuple[bytes, bool]] = []
    idx = index

    while len(level) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            if i == (idx ^ 1) - 1 if (idx % 2 == 1) else i == idx + 1:
                pass  # no-op: clarity
            if i == idx or i == idx - 1 and idx % 2 == 1:
                # Collect sibling
                if idx % 2 == 0:  # left node
                    sibling = right
                    proof.append((sibling, True))  # sibling is right
                else:
                    sibling = left
                    proof.append((sibling, False))  # sibling is left
            combined = _pair_combine(left, right, params)
            nxt.append(combined)

        idx //= 2
        level = nxt

    return proof


def merkle_verify(leaf_hash: bytes, proof: Sequence[Tuple[bytes, bool]], root: bytes, params: MerkleParams) -> bool:
    """
    Verify Merkle proof from a leaf hash to root.
    Each proof element: (sibling_hash, is_right_sibling)
    """
    acc = leaf_hash
    for sibling, is_right in proof:
        left, right = (acc, sibling) if is_right else (sibling, acc)
        acc = _pair_combine(left, right, params)
    return acc == root


# ---------------------------
# Measurement helpers
# ---------------------------

@dataclass
class Metrics:
    seconds: float
    bytes_processed: int
    num_leaves: int
    peak_kib: Optional[float] = None

    @property
    def mib_per_s(self) -> float:
        if self.seconds <= 0:
            return float("inf")
        return (self.bytes_processed / (1024 * 1024)) / self.seconds

    @property
    def leaves_per_s(self) -> float:
        if self.seconds <= 0:
            return float("inf")
        return self.num_leaves / self.seconds


class Stopwatch:
    def __init__(self, track_memory: bool = True):
        self.track_memory = track_memory
        self.start_t = 0.0
        self.end_t = 0.0
        self.peak_kib: Optional[float] = None

    def __enter__(self):
        if self.track_memory:
            tracemalloc.start()
        self.start_t = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.end_t = time.perf_counter()
        if self.track_memory:
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            self.peak_kib = peak / 1024.0

    @property
    def seconds(self) -> float:
        return self.end_t - self.start_t


def _format_metrics(title: str, m: Metrics) -> str:
    mem = f", peak={m.peak_kib:.1f} KiB" if m.peak_kib is not None else ""
    return (f"{title}: time={m.seconds:.6f}s, "
            f"throughput={m.mib_per_s:.2f} MiB/s, "
            f"leaves={m.leaves_per_s:.0f}/s{mem}")


# ---------------------------
# Benchmark kernels
# ---------------------------

def bench_build_root_raw(leaves: Sequence[bytes], params: MerkleParams) -> Tuple[bytes, Metrics]:
    data_bytes = sum(len(x) for x in leaves)
    with Stopwatch() as sw:
        root = merkle_root_from_leaves(leaves, params)
    return root, Metrics(sw.seconds, data_bytes, len(leaves), sw.peak_kib)


def bench_build_root_prehash(leaves: Sequence[bytes], params: MerkleParams) -> Tuple[bytes, Metrics]:
    # Pre-hash leaves outside of build to isolate internal-node hashing
    hashed = [params.hash_fn(x) for x in leaves]
    data_bytes = sum(len(x) for x in hashed)
    with Stopwatch() as sw:
        root = merkle_root_from_hashed(hashed, params)
    return root, Metrics(sw.seconds, data_bytes, len(hashed), sw.peak_kib)


def bench_make_proof(hashed_leaves: Sequence[bytes], params: MerkleParams, index: int) -> Tuple[List[Tuple[bytes, bool]], Metrics]:
    data_bytes = len(hashed_leaves) * (len(hashed_leaves[0]) if hashed_leaves else 32)
    with Stopwatch() as sw:
        proof = merkle_proof(hashed_leaves, index, params)
    return proof, Metrics(sw.seconds, data_bytes, len(hashed_leaves), sw.peak_kib)


def bench_verify_proof(leaf_hash: bytes, proof: Sequence[Tuple[bytes, bool]], root: bytes, params: MerkleParams) -> Tuple[bool, Metrics]:
    data_bytes = len(leaf_hash) + sum(len(sib) for sib, _ in proof) + len(root)
    with Stopwatch() as sw:
        ok = merkle_verify(leaf_hash, proof, root, params)
    return ok, Metrics(sw.seconds, data_bytes, len(proof) + 1, sw.peak_kib)


# ---------------------------
# Pytest integration
# ---------------------------

def _have_pytest_benchmark(request) -> bool:
    try:
        # Will raise if fixture is unavailable
        request.getfixturevalue("benchmark")
        return True
    except Exception:
        return False


def _run_under_pytest_benchmark(benchmark, func: Callable[[], object]) -> object:
    # Delegate to plugin timing
    return benchmark(func)


def _run_benchmark_fallback(func: Callable[[], object]) -> Tuple[object, float]:
    # Manual timing when plugin is absent
    start = time.perf_counter()
    res = func()
    end = time.perf_counter()
    return res, end - start


# If running under pytest, the following tests will be discovered.
try:
    import pytest  # type: ignore
except Exception:
    pytest = None  # Allow CLI use without pytest


if pytest is not None:
    @pytest.fixture(scope="module", params=["sha256", "blake2b-256"])
    def algo(request) -> str:
        return request.param

    @pytest.fixture(scope="module", params=[4096, 16384])  # adjust upper bound to your CI capacity
    def leaves_count(request) -> int:
        return request.param

    @pytest.fixture(scope="module", params=[32, 256, 1024])
    def leaf_size(request) -> int:
        return request.param

    @pytest.fixture(scope="module")
    def dataset(leaves_count: int, leaf_size: int):
        return deterministic_bytes(leaves_count, leaf_size, seed=1337)

    @pytest.fixture(scope="module")
    def params(algo: str) -> MerkleParams:
        return MerkleParams(hash_fn=resolve_hash(algo), sorted_pairs=False)

    def test_merkle_correctness(dataset, params):
        # Build root two ways and assert equality
        root_raw = merkle_root_from_leaves(dataset, params)
        hashed = [params.hash_fn(x) for x in dataset]
        root_hashed = merkle_root_from_hashed(hashed, params)
        assert root_raw == root_hashed, "Roots mismatch between raw and pre-hashed paths"

        # Proof/verify for multiple indices
        for idx in (0, len(hashed) // 2, len(hashed) - 1):
            proof = merkle_proof(hashed, idx, params)
            ok = merkle_verify(hashed[idx], proof, root_hashed, params)
            assert ok, f"Verification failed for index {idx}"

    def test_bench_build_root(request, dataset, params, leaves_count, leaf_size, algo):
        have_bench = _have_pytest_benchmark(request)
        title = f"build_root_raw[{algo}|N={leaves_count}|S={leaf_size}]"

        def kernel():
            root, _m = bench_build_root_raw(dataset, params)
            return root

        if have_bench:
            result = _run_under_pytest_benchmark(request.getfixturevalue("benchmark"), kernel)
            assert isinstance(result, bytes)
        else:
            root, m = bench_build_root_raw(dataset, params)
            print(_format_metrics(title, m))
            assert isinstance(root, bytes)

    def test_bench_build_root_prehash(request, dataset, params, leaves_count, leaf_size, algo):
        have_bench = _have_pytest_benchmark(request)
        title = f"build_root_prehash[{algo}|N={leaves_count}|S={leaf_size}]"

        def kernel():
            root, _m = bench_build_root_prehash(dataset, params)
            return root

        if have_bench:
            result = _run_under_pytest_benchmark(request.getfixturevalue("benchmark"), kernel)
            assert isinstance(result, bytes)
        else:
            root, m = bench_build_root_prehash(dataset, params)
            print(_format_metrics(title, m))
            assert isinstance(root, bytes)

    def test_bench_proof_and_verify(request, dataset, params, leaves_count, leaf_size, algo):
        have_bench = _have_pytest_benchmark(request)
        hashed = [params.hash_fn(x) for x in dataset]
        root = merkle_root_from_hashed(hashed, params)

        # Probe three indices to catch worst/average/best-ish cases
        indices = [0, len(hashed) // 2, len(hashed) - 1]
        for idx in indices:
            title_proof = f"make_proof[{algo}|N={leaves_count}|S={leaf_size}|i={idx}]"
            title_verify = f"verify_proof[{algo}|N={leaves_count}|S={leaf_size}|i={idx}]"

            def k_proof():
                pf, _m = bench_make_proof(hashed, params, idx)
                return pf

            if have_bench:
                proof = _run_under_pytest_benchmark(request.getfixturevalue("benchmark"), k_proof)
            else:
                proof, m = bench_make_proof(hashed, params, idx)
                print(_format_metrics(title_proof, m))

            # Verify
            leaf_h = hashed[idx]

            def k_verify():
                ok, _m = bench_verify_proof(leaf_h, proof if have_bench else proof, root, params)
                return ok

            if have_bench:
                ok = _run_under_pytest_benchmark(request.getfixturevalue("benchmark"), k_verify)
                assert ok is True
            else:
                ok, m2 = bench_verify_proof(leaf_h, proof, root, params)
                print(_format_metrics(title_verify, m2))
                assert ok is True


# ---------------------------
# CLI runner
# ---------------------------

def run_cli(algo: str, leaves: int, leaf_size: int, prehash: bool, sorted_pairs: bool, seed: int, proofs: int):
    params = MerkleParams(hash_fn=resolve_hash(algo), sorted_pairs=sorted_pairs)
    blobs = deterministic_bytes(leaves, leaf_size, seed=seed)

    if prehash:
        root, m = bench_build_root_prehash(blobs, params)
        print(_format_metrics(f"CLI build_root_prehash[{algo}|N={leaves}|S={leaf_size}]", m))
        hashed = [params.hash_fn(x) for x in blobs]
    else:
        root, m = bench_build_root_raw(blobs, params)
        print(_format_metrics(f"CLI build_root_raw[{algo}|N={leaves}|S={leaf_size}]", m))
        hashed = [params.hash_fn(x) for x in blobs]
        # root should match the pre-hashed path
        root2 = merkle_root_from_hashed(hashed, params)
        if root != root2:
            print("Warning: root mismatch between raw and prehash paths")

    # Proofs
    if leaves > 0 and proofs > 0:
        step = max(1, leaves // proofs)
        indices = list(range(0, leaves, step))[:proofs]
        for idx in indices:
            proof, m1 = bench_make_proof(hashed, params, idx)
            print(_format_metrics(f"CLI make_proof[{algo}|N={leaves}|i={idx}]", m1))
            ok, m2 = bench_verify_proof(hashed[idx], proof, root, params)
            print(_format_metrics(f"CLI verify_proof[{algo}|N={leaves}|i={idx}]", m2))
            if not ok:
                print(f"Verification failed for index {idx}")
                sys.exit(2)


def run_cli_matrix():
    matrix = [
        ("sha256", 4096, 32),
        ("sha256", 16384, 256),
        ("sha256", 16384, 1024),
        ("blake2b-256", 4096, 32),
        ("blake2b-256", 16384, 256),
        ("blake2b-256", 16384, 1024),
    ]
    for algo, n, s in matrix:
        print("=" * 80)
        print(f"Case: algo={algo}, leaves={n}, leaf_size={s}, prehash=False")
        run_cli(algo=algo, leaves=n, leaf_size=s, prehash=False,
                sorted_pairs=False, seed=1337, proofs=3)
        print(f"Case: algo={algo}, leaves={n}, leaf_size={s}, prehash=True")
        run_cli(algo=algo, leaves=n, leaf_size=s, prehash=True,
                sorted_pairs=False, seed=1337, proofs=3)


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Merkle benchmark runner (CLI)")
    p.add_argument("--algo", type=str, default="sha256", help="sha256 | blake2b-256")
    p.add_argument("--leaves", type=int, default=16384, help="number of leaves")
    p.add_argument("--leaf-size", type=int, default=1024, help="size of each leaf in bytes")
    p.add_argument("--prehash", action="store_true", help="pre-hash leaves before building tree")
    p.add_argument("--sorted-pairs", action="store_true", help="lexicographically sort pairs before combine")
    p.add_argument("--seed", type=int, default=1337, help="deterministic generator seed")
    p.add_argument("--proofs", type=int, default=3, help="number of proof/verify samples")
    p.add_argument("--matrix", action="store_true", help="run built-in scenario matrix")
    return p.parse_args(argv)


if __name__ == "__main__":
    args = _parse_args()
    if args.matrix:
        run_cli_matrix()
    else:
        run_cli(
            algo=args.algo,
            leaves=args.leaves,
            leaf_size=args.leaf_size,
            prehash=args.prehash,
            sorted_pairs=args.sorted_pairs,
            seed=args.seed,
            proofs=args.proofs,
        )
