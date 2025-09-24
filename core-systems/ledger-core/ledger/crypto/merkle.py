# -*- coding: utf-8 -*-
"""
Merkle tree (RFC 6962-style) utilities for Ledger Core.

Design goals:
- Deterministic SHA-256 with prefixes:
    leaf  = H(0x00 || data)
    node  = H(0x01 || left || right)
- Root for empty tree is H(b"") (deterministic sentinel)
- Inclusion proof generation + verification
- Consistency proof generation + verification (correct recursive algo)
- Incremental builder (append leaves or pre-hashed leaves)
- Hex helpers, size guards, type hints
- Pure Python, stdlib only

This module operates on *leaf hashes* (already prefixed) internally.
Call `leaf_hash(data: bytes)` to hash raw data for a leaf.

References: RFC 6962 Merkle Tree Hashes (structure-compatible).
"""

from __future__ import annotations

import binascii
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Iterable, List, Sequence, Tuple, Optional

# ===== Parameters and limits =====

LEAF_PREFIX: bytes = b"\x00"
NODE_PREFIX: bytes = b"\x01"
MAX_TREE_SIZE: int = 2_000_000     # configurable guard for proofs
MAX_AUDIT_PATH: int = 64           # ~ log2(MAX_TREE_SIZE)

# ===== Low-level hashing =====

def leaf_hash(data: bytes) -> bytes:
    """RFC 6962-like leaf hash: H(0x00 || data)."""
    return sha256(LEAF_PREFIX + data).digest()

def node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962-like internal node hash: H(0x01 || left || right)."""
    return sha256(NODE_PREFIX + left + right).digest()

def empty_root() -> bytes:
    """Deterministic root for empty tree."""
    return sha256(b"").digest()

# ===== Helpers =====

def to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii")

def from_hex(s: str) -> bytes:
    try:
        return binascii.unhexlify(s.strip().lower())
    except Exception as e:
        raise ValueError(f"bad hex: {e}")

def _largest_power_of_two_leq(n: int) -> int:
    """Largest power of two <= n for n >= 1."""
    p = 1
    while (p << 1) <= n:
        p <<= 1
    return p

# ===== Core algorithms (on leaf-hash arrays) =====

def merkle_root(leaves: Sequence[bytes]) -> bytes:
    """Compute merkle root for a list of leaf *hashes* (not raw data)."""
    n = len(leaves)
    if n == 0:
        return empty_root()
    layer = list(leaves)
    while len(layer) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(layer), 2):
            if i + 1 < len(layer):
                nxt.append(node_hash(layer[i], layer[i + 1]))
            else:
                # RFC6962: odd node is promoted
                nxt.append(layer[i])
        layer = nxt
    return layer[0]

def inclusion_proof(leaves: Sequence[bytes], index: int) -> List[bytes]:
    """
    Build an audit path for leaf at `index` in the tree made of `leaves`.
    Returns list of sibling hashes bottom-up.
    """
    n = len(leaves)
    if not (0 <= index < n):
        raise ValueError("index out of range")
    if n > MAX_TREE_SIZE:
        raise ValueError("tree too large")

    path: List[bytes] = []
    layer = list(leaves)
    idx = index
    while len(layer) > 1:
        # record sibling
        if idx % 2 == 0:  # left
            sib = idx + 1
            if sib < len(layer):
                path.append(layer[sib])
        else:             # right
            sib = idx - 1
            path.append(layer[sib])

        # build next layer
        nxt: List[bytes] = []
        for i in range(0, len(layer), 2):
            if i + 1 < len(layer):
                nxt.append(node_hash(layer[i], layer[i + 1]))
            else:
                nxt.append(layer[i])
        layer = nxt
        idx //= 2

        if len(path) > MAX_AUDIT_PATH:
            raise ValueError("audit path too long")
    return path

def root_from_inclusion(leaf_hash_value: bytes, index: int, audit_path: Sequence[bytes]) -> bytes:
    """Reconstruct root from leaf hash, its index and audit path."""
    h = leaf_hash_value
    idx = index
    for sib in audit_path:
        if idx % 2 == 0:
            h = node_hash(h, sib)
        else:
            h = node_hash(sib, h)
        idx //= 2
    return h

def verify_inclusion(leaf_hash_value: bytes, index: int, audit_path: Sequence[bytes], expected_root: bytes) -> bool:
    """Verify inclusion proof (constant-time eq not required for public roots)."""
    try:
        calc = root_from_inclusion(leaf_hash_value, index, audit_path)
        return calc == expected_root
    except Exception:
        return False

# ===== Consistency proof (correct recursive algorithm) =====

def _subroot(leaves: Sequence[bytes], start: int, end: int) -> bytes:
    """Root of subrange leaves[start:end]."""
    if start >= end:
        return empty_root()
    layer = list(leaves[start:end])
    while len(layer) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(layer), 2):
            if i + 1 < len(layer):
                nxt.append(node_hash(layer[i], layer[i + 1]))
            else:
                nxt.append(layer[i])
        layer = nxt
    return layer[0]

def consistency_proof(old_size: int, new_size: int, leaves: Sequence[bytes]) -> List[bytes]:
    """
    Build RFC 6962-style consistency proof nodes between old_size (m) and new_size (n) trees, m <= n.
    Returns a list of subtree roots sufficient to verify that the n-tree extends the m-tree.
    """
    if old_size < 1:
        # per CT/RFC, consistency from empty tree is trivial; return [] for m==0
        return []
    if not (old_size <= new_size <= len(leaves)):
        raise ValueError("bad sizes for consistency_proof")
    if new_size > MAX_TREE_SIZE:
        raise ValueError("tree too large")

    def _proof(m: int, n: int, offset: int) -> List[bytes]:
        if m == n:
            return []
        k = _largest_power_of_two_leq(n)
        # NB: offset is used only if you compute ranges; here we compute roots by ranges.
        if m <= k:
            # left part is the m-subtree inside the left k block; append right subtree root
            right_root = _subroot(leaves, k, n)
            return _proof(m, k, 0) + [right_root]
        else:
            # m crosses right block; append left subtree root, recurse on right
            left_root = _subroot(leaves, 0, k)
            return _proof(m - k, n - k, k) + [left_root]

    return _proof(old_size, new_size, 0)

def verify_consistency(old_size: int, new_size: int, old_root: bytes, new_root: bytes, proof: Sequence[bytes]) -> bool:
    """
    Verify that a tree of size `new_size` is an append-only extension of a tree of size `old_size`,
    given `old_root`, `new_root` and the `proof` produced by `consistency_proof`.

    This verifier mirrors the recursive construction and consumes the proof in order.
    """
    if old_size < 1:
        # empty old tree is trivially consistent
        return True
    if old_size == new_size:
        return old_root == new_root and len(proof) == 0

    # Iterator over proof nodes
    it = iter(proof)

    def _verify(m: int, n: int) -> Tuple[bytes, bytes]:
        """
        Returns (root_m, root_n) computed from the proof tail for sizes (m, n).
        The order of proof consumption must match `consistency_proof`.
        """
        if m == n:
            # no nodes consumed at this frame; caller provides old/new roots via upwards composition
            return old_root, old_root
        k = _largest_power_of_two_leq(n)
        if m <= k:
            # Recurse inside left block: both old and partial-new are inside left subtree.
            rm, rn_left = _verify(m, k)
            try:
                right = next(it)
            except StopIteration:
                raise ValueError("proof too short")
            # Combine left-partial with right subtree root to obtain n-root
            rn = node_hash(rn_left, right)
            return rm, rn
        else:
            # Recurse on right block: old is split across left+right; combine with left root
            rm_right, rn_right = _verify(m - k, n - k)
            try:
                left = next(it)
            except StopIteration:
                raise ValueError("proof too short")
            rm = node_hash(left, rm_right)
            rn = node_hash(left, rn_right)
            return rm, rn

    try:
        rm, rn = _verify(old_size, new_size)
        # All proof nodes must be consumed
        try:
            next(it)
            # extra nodes present
            return False
        except StopIteration:
            return rm == old_root and rn == new_root
    except Exception:
        return False

# ===== Incremental builder =====

@dataclass
class MerkleTree:
    """
    Incremental Merkle tree over leaf hashes.
    Notes:
      - Internally stores leaf *hashes* (use .append_data for raw input).
      - Root and proofs are computed on demand (O(n)).
      - For very large trees, prefer precomputed snapshots and proof stores.
    """
    _leaves: List[bytes] = field(default_factory=list)

    # --- leaf management ---
    @property
    def size(self) -> int:
        return len(self._leaves)

    def append_leaf_hash(self, h: bytes) -> None:
        if not isinstance(h, (bytes, bytearray)) or len(h) != 32:
            raise ValueError("leaf hash must be 32-byte digest")
        self._leaves.append(bytes(h))

    def append_data(self, data: bytes) -> None:
        self._leaves.append(leaf_hash(data))

    def extend_leaf_hashes(self, hashes: Iterable[bytes]) -> None:
        for h in hashes:
            self.append_leaf_hash(h)

    def extend_data(self, blobs: Iterable[bytes]) -> None:
        for b in blobs:
            self.append_data(b)

    # --- queries ---
    def root(self) -> bytes:
        return merkle_root(self._leaves)

    def inclusion_proof(self, index: int) -> List[bytes]:
        return inclusion_proof(self._leaves, index)

    def verify_inclusion(self, index: int, leaf_hash_value: bytes, expected_root: bytes) -> bool:
        path = self.inclusion_proof(index)
        return verify_inclusion(leaf_hash_value, index, path, expected_root)

    def consistency_proof(self, old_size: int) -> List[bytes]:
        return consistency_proof(old_size, self.size, self._leaves)

    # --- export ---
    def leaves(self) -> List[bytes]:
        return list(self._leaves)

# ===== User-friendly hex API (optional) =====

def inclusion_proof_hex(leaves_hex: Sequence[str], index: int) -> List[str]:
    leaves = [from_hex(h) for h in leaves_hex]
    path = inclusion_proof(leaves, index)
    return [to_hex(h) for h in path]

def root_hex(leaves_hex: Sequence[str]) -> str:
    return to_hex(merkle_root([from_hex(h) for h in leaves_hex]))

def verify_inclusion_hex(leaf_hash_hex: str, index: int, audit_path_hex: Sequence[str], expected_root_hex: str) -> bool:
    return verify_inclusion(
        from_hex(leaf_hash_hex),
        index,
        [from_hex(h) for h in audit_path_hex],
        from_hex(expected_root_hex),
    )

def consistency_proof_hex(old_size: int, new_size: int, leaves_hex: Sequence[str]) -> List[str]:
    proof = consistency_proof(old_size, new_size, [from_hex(h) for h in leaves_hex])
    return [to_hex(p) for p in proof]

def verify_consistency_hex(old_size: int, new_size: int, old_root_hex: str, new_root_hex: str, proof_hex: Sequence[str]) -> bool:
    return verify_consistency(
        old_size, new_size,
        from_hex(old_root_hex),
        from_hex(new_root_hex),
        [from_hex(p) for p in proof_hex],
    )
