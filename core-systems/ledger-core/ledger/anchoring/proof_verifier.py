# ledger/anchoring/proof_verifier.py
# -*- coding: utf-8 -*-
"""
Industrial-grade proof verification for anchoring subsystem.

Features:
- Merkle inclusion proof verification (single-branch) with explicit sibling directions.
- Deterministic hashers: sha256, keccak256, blake2b-256.
- Batch verification (multi-leaf) via independent branch verification + root consistency check.
- Anchor receipt checks against provided block header/state root adapter.
- Constant-time comparisons to avoid timing side-channels.
- Strict input validation, explicit exceptions, rich logging, audit trail hashing.
- Metrics/trace hooks via lightweight Protocol interfaces (no external deps).

This module avoids I/O and network calls; integrate via your adapters.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Iterable, List, Optional, Protocol, Sequence, Tuple, runtime_checkable

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("ledger.anchoring.proof_verifier")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter(
        fmt="%(asctime)s %(levelname)s [%(name)s] %(message)s"
    ))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class ProofError(Exception):
    """Base class for proof-related errors."""

class InvalidProofFormat(ProofError):
    """Raised when a proof structure is malformed."""

class HashAlgorithmError(ProofError):
    """Raised when a requested hash algorithm is unsupported or misused."""

class VerificationFailed(ProofError):
    """Raised when a verification step fails."""

# ---------------------------------------------------------------------------
# Hashers
# ---------------------------------------------------------------------------

class HashAlg(str, Enum):
    SHA256 = "sha256"
    KECCAK256 = "keccak256"
    BLAKE2B_256 = "blake2b_256"


def _hash_sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hash_keccak256(data: bytes) -> bytes:
    try:
        # Python 3.11+: hashlib supports 'sha3_256' (Keccak-f[1600] / NIST SHA3-256).
        # Many chains colloquially say "keccak256" but mean SHA3-256 standardized.
        return hashlib.sha3_256(data).digest()
    except Exception as exc:
        raise HashAlgorithmError("Keccak/SHA3-256 is not supported by this runtime") from exc


def _hash_blake2b_256(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()


_HASHERS: dict[HashAlg, Callable[[bytes], bytes]] = {
    HashAlg.SHA256: _hash_sha256,
    HashAlg.KECCAK256: _hash_keccak256,
    HashAlg.BLAKE2B_256: _hash_blake2b_256,
}

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _const_eq(a: bytes, b: bytes) -> bool:
    """Constant-time equality."""
    return hmac.compare_digest(a, b)


def _ensure_bytes(name: str, v: bytes) -> None:
    if not isinstance(v, (bytes, bytearray)):
        raise InvalidProofFormat(f"{name} must be bytes, got {type(v)}")
    if len(v) == 0:
        raise InvalidProofFormat(f"{name} must be non-empty bytes")


def _get_hasher(alg: HashAlg | str) -> Callable[[bytes], bytes]:
    try:
        if isinstance(alg, str):
            alg = HashAlg(alg.lower())
        return _HASHERS[alg]
    except Exception as exc:
        raise HashAlgorithmError(f"Unsupported hash algorithm: {alg}") from exc


def _safe_concat(left: bytes, right: bytes) -> bytes:
    # Explicit concatenation, easy to audit.
    return left + right

# ---------------------------------------------------------------------------
# Protocols for integrations (no external deps)
# ---------------------------------------------------------------------------

@runtime_checkable
class MetricSink(Protocol):
    def incr(self, name: str, value: int = 1, *, tags: Optional[dict] = None) -> None: ...
    def timing(self, name: str, ms: float, *, tags: Optional[dict] = None) -> None: ...


@runtime_checkable
class TraceSink(Protocol):
    def span(self, name: str, **kwargs) -> "TraceSpan": ...


class TraceSpan:
    """No-op span if no tracer supplied."""
    def __init__(self, name: str):
        self.name = name
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb): return False
    def set_tag(self, key: str, value):  # noqa: D401
        """Attach key/value to span."""
        return self


@runtime_checkable
class BlockHeader(Protocol):
    """
    Minimal interface for a block header object used by anchoring.
    Provide one or both of:
      - tx_merkle_root: bytes  (Bitcoin-like)
      - state_root: bytes      (EVM-like)
    """
    @property
    def chain_id(self) -> str: ...
    @property
    def height(self) -> int: ...
    @property
    def tx_merkle_root(self) -> Optional[bytes]: ...
    @property
    def state_root(self) -> Optional[bytes]: ...
    @property
    def timestamp(self) -> int: ...


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Sibling:
    """
    Sibling hash with explicit position relative to running hash.
    pos: 'L' means sibling is left of the current hash; 'R' means right.
    """
    hash: bytes
    pos: str  # 'L' or 'R'

    def __post_init__(self):
        _ensure_bytes("Sibling.hash", self.hash)
        if self.pos not in ("L", "R"):
            raise InvalidProofFormat("Sibling.pos must be 'L' or 'R'")


@dataclass(frozen=True)
class MerkleProof:
    """
    Single-branch Merkle inclusion proof.
    - leaf: raw leaf bytes, preimage for the first hash (leaf hashing policy configurable).
    - siblings: ordered list from leaf-level upward to root (bottom -> top).
    - already_hashed: if True, 'leaf' is treated as already hashed; otherwise leaf is hashed first.
    """
    leaf: bytes
    siblings: Tuple[Sibling, ...]
    already_hashed: bool = False

    def __post_init__(self):
        _ensure_bytes("MerkleProof.leaf", self.leaf)
        if len(self.siblings) == 0:
            raise InvalidProofFormat("MerkleProof requires at least one sibling")


@dataclass(frozen=True)
class BatchMerkleProof:
    """
    Batch of independent single-branch proofs expected to converge to the same root.
    This is deterministic and easy to audit; for true multiproof compression use a specialized format.
    """
    proofs: Tuple[MerkleProof, ...]
    expected_root: bytes

    def __post_init__(self):
        if len(self.proofs) == 0:
            raise InvalidProofFormat("BatchMerkleProof.proofs must be non-empty")
        _ensure_bytes("BatchMerkleProof.expected_root", self.expected_root)


@dataclass(frozen=True)
class AnchorReceipt:
    """
    Anchoring receipt — cryptographic commitment that an application root was included on-chain.

    Fields:
    - chain_id: logical ID of the chain (e.g., 'bitcoin-mainnet', 'ethereum-mainnet').
    - anchor_root: bytes committed root (e.g., Merkle root of your off-chain batch).
    - anchor_location: description of where this root is stored in the chain context
        (e.g., 'tx.op_return', 'calldata', 'event.topic[1]', 'stateRoot', etc.).
    - tx_hash: optional transaction hash if applicable.
    - block_height: the height of the containing block.
    - block_root_type: which header field should match anchor_root ('tx_merkle_root' or 'state_root'), or None when not applicable.
    - signature: optional signature of a trusted anchoring service (bytes).
    - signer_id: optional signer identity string.
    """
    chain_id: str
    anchor_root: bytes
    anchor_location: str
    block_height: int
    block_root_type: Optional[str] = None  # 'tx_merkle_root' | 'state_root' | None
    tx_hash: Optional[bytes] = None
    signature: Optional[bytes] = None
    signer_id: Optional[str] = None

    def __post_init__(self):
        if not self.chain_id or not isinstance(self.chain_id, str):
            raise InvalidProofFormat("AnchorReceipt.chain_id must be non-empty str")
        _ensure_bytes("AnchorReceipt.anchor_root", self.anchor_root)
        if not self.anchor_location or not isinstance(self.anchor_location, str):
            raise InvalidProofFormat("AnchorReceipt.anchor_location must be non-empty str")
        if not isinstance(self.block_height, int) or self.block_height < 0:
            raise InvalidProofFormat("AnchorReceipt.block_height must be >= 0")
        if self.tx_hash is not None:
            _ensure_bytes("AnchorReceipt.tx_hash", self.tx_hash)
        if self.signature is not None:
            _ensure_bytes("AnchorReceipt.signature", self.signature)

# ---------------------------------------------------------------------------
# Signature verifier Protocol (optional)
# ---------------------------------------------------------------------------

@runtime_checkable
class SignatureVerifier(Protocol):
    """
    Implement signature verification for receipts signed by an anchoring authority.
    """
    def verify(self, message: bytes, signature: bytes, signer_id: Optional[str] = None) -> bool: ...

# ---------------------------------------------------------------------------
# Proof Verifier
# ---------------------------------------------------------------------------

@dataclass
class ProofVerifier:
    """
    Verifier for Merkle inclusion proofs and anchor receipts.

    Parameters:
    - hash_alg: HashAlg | str, default 'sha256'
    - metric_sink: optional metrics integration
    - trace_sink: optional tracing integration
    - leaf_prefix: optional domain separation tag prepended before leaf hashing
    - node_prefix: optional domain separation tag used for internal node hashing
    - upper_bound_siblings: safety limit for path length to avoid DoS with huge proofs
    """
    hash_alg: HashAlg | str = HashAlg.SHA256
    metric_sink: Optional[MetricSink] = None
    trace_sink: Optional[TraceSink] = None
    leaf_prefix: bytes = field(default_factory=lambda: b"\x00LEAF")
    node_prefix: bytes = field(default_factory=lambda: b"\x01NODE")
    upper_bound_siblings: int = 1024

    def __post_init__(self):
        self._hash = _get_hasher(self.hash_alg)
        if self.upper_bound_siblings <= 0 or self.upper_bound_siblings > 1_000_000:
            raise InvalidProofFormat("upper_bound_siblings out of sane range")

    # ---------------------------- Public API ---------------------------- #

    def verify_merkle_inclusion(self, proof: MerkleProof, expected_root: bytes) -> bool:
        """
        Verify a single-branch Merkle proof.

        Sibling order: must be from leaf level up to root.
        Each Sibling.pos indicates whether sibling sits Left (L) or Right (R) relative to the running hash.

        Returns True on success, raises VerificationFailed on mismatch or InvalidProofFormat on malformed input.
        """
        _ensure_bytes("expected_root", expected_root)
        if len(proof.siblings) > self.upper_bound_siblings:
            raise InvalidProofFormat("Proof path length exceeds upper bound")

        with self._trace("verify_merkle_inclusion") as span:
            span.set_tag("siblings", len(proof.siblings))
            try:
                running = proof.leaf if proof.already_hashed else self._hash(self.leaf_prefix + proof.leaf)

                for idx, sib in enumerate(proof.siblings):
                    _ensure_bytes(f"siblings[{idx}].hash", sib.hash)
                    if sib.pos == "L":
                        running = self._hash(self.node_prefix + _safe_concat(sib.hash, running))
                    else:  # "R"
                        running = self._hash(self.node_prefix + _safe_concat(running, sib.hash))

                if not _const_eq(running, expected_root):
                    self._metric("proof.verify.failed")
                    logger.warning("Merkle proof mismatch: computed root != expected_root")
                    raise VerificationFailed("Merkle proof failed")

                self._metric("proof.verify.ok")
                return True
            except VerificationFailed:
                raise
            except Exception as exc:
                logger.exception("Error during Merkle inclusion verification")
                raise InvalidProofFormat("Verification aborted due to processing error") from exc

    def verify_batch(self, batch: BatchMerkleProof) -> bool:
        """
        Verify a batch of independent single-branch proofs against the same expected root.
        Deterministic, parallelizable upstream.

        Returns True if all pass; raises VerificationFailed on the first failure.
        """
        with self._trace("verify_batch") as span:
            span.set_tag("batch_size", len(batch.proofs))
            for i, p in enumerate(batch.proofs):
                ok = self.verify_merkle_inclusion(p, batch.expected_root)
                if not ok:
                    self._metric("batch.verify.failed")
                    raise VerificationFailed(f"Batch verification failed at index {i}")
            self._metric("batch.verify.ok", value=len(batch.proofs))
            return True

    def verify_anchor_against_header(
        self,
        receipt: AnchorReceipt,
        header: BlockHeader,
        *,
        require_root_match: bool = True,
        signature_verifier: Optional[SignatureVerifier] = None,
    ) -> bool:
        """
        Verify an AnchorReceipt against a provided BlockHeader.

        Steps:
        1) chain_id equality
        2) height equality
        3) (optional) signature verification if signature present and verifier provided
        4) (optional) root equality check vs field specified by receipt.block_root_type

        Returns True on success; raises VerificationFailed on mismatch.
        """
        with self._trace("verify_anchor_against_header") as span:
            try:
                if header.chain_id != receipt.chain_id:
                    raise VerificationFailed("chain_id mismatch")

                if header.height != receipt.block_height:
                    raise VerificationFailed("block height mismatch")

                if receipt.signature is not None:
                    if signature_verifier is None:
                        raise VerificationFailed("signature present but no verifier provided")
                    message = self._anchor_message(receipt)
                    if not signature_verifier.verify(message, receipt.signature, receipt.signer_id):
                        raise VerificationFailed("signature verification failed")

                if require_root_match and receipt.block_root_type:
                    root_field = receipt.block_root_type
                    if root_field not in ("tx_merkle_root", "state_root"):
                        raise InvalidProofFormat("Unsupported block_root_type in receipt")

                    header_root = getattr(header, root_field)
                    if header_root is None:
                        raise VerificationFailed(f"Header missing required root field: {root_field}")

                    if not _const_eq(header_root, receipt.anchor_root):
                        raise VerificationFailed("anchor_root does not match header root")

                self._metric("anchor.verify.ok")
                return True
            except VerificationFailed as vf:
                self._metric("anchor.verify.failed")
                logger.warning("Anchor verification failed: %s", vf)
                raise
            except Exception as exc:
                logger.exception("Error during anchor verification")
                raise InvalidProofFormat("Anchor verification aborted due to processing error") from exc

    # ---------------------------- Helpers ---------------------------- #

    def compute_root_from_proof(self, proof: MerkleProof) -> bytes:
        """
        Deterministically compute the Merkle root from a proof (without comparing).
        """
        if len(proof.siblings) > self.upper_bound_siblings:
            raise InvalidProofFormat("Proof path length exceeds upper bound")
        running = proof.leaf if proof.already_hashed else self._hash(self.leaf_prefix + proof.leaf)
        for sib in proof.siblings:
            running = (self._hash(self.node_prefix + _safe_concat(sib.hash, running))
                       if sib.pos == "L"
                       else self._hash(self.node_prefix + _safe_concat(running, sib.hash)))
        return running

    def audit_trail_digest(self, proof: MerkleProof, *, include_root: Optional[bytes] = None) -> bytes:
        """
        Produce a deterministic audit digest of the proof content for logging/attestation.
        This is NOT a security primitive by itself; use for traceability.
        """
        h = self._hash
        acc = b"AUDITv1|" + self._to_bytes(self.hash_alg)
        acc = h(acc + b"|LEAF|" + proof.leaf + (b"|H" if proof.already_hashed else b"|P"))
        for i, sib in enumerate(proof.siblings):
            acc = h(acc + f"|S{i}|".encode("ascii") + sib.pos.encode("ascii") + sib.hash)
        if include_root:
            acc = h(acc + b"|ROOT|" + include_root)
        return acc

    def _anchor_message(self, r: AnchorReceipt) -> bytes:
        """
        Canonical message for signature verification: domain-separated concatenation.
        """
        parts = [
            b"ANCHORv1|",
            r.chain_id.encode("utf-8"),
            b"|H|", str(r.block_height).encode("ascii"),
            b"|LOC|", r.anchor_location.encode("utf-8"),
            b"|ROOT|", r.anchor_root,
        ]
        if r.tx_hash:
            parts.extend([b"|TX|", r.tx_hash])
        return b"".join(parts)

    def _metric(self, name: str, *, value: int = 1) -> None:
        if self.metric_sink:
            try:
                self.metric_sink.incr(name, value=value)
            except Exception:
                logger.debug("Metric sink failed", exc_info=True)

    def _trace(self, name: str):
        if self.trace_sink:
            try:
                return self.trace_sink.span(name)
            except Exception:
                logger.debug("Trace sink failed, using no-op span", exc_info=True)
        return TraceSpan(name)

    @staticmethod
    def _to_bytes(alg: HashAlg | str) -> bytes:
        return (alg.value if isinstance(alg, HashAlg) else alg).encode("ascii")

# ---------------------------------------------------------------------------
# Example minimal adapters (for illustration/testing; replace in production)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SimpleHeader:
    chain_id: str
    height: int
    timestamp: int
    tx_merkle_root: Optional[bytes] = None
    state_root: Optional[bytes] = None

    # matches BlockHeader Protocol


class NoopSignatureVerifier:
    def verify(self, message: bytes, signature: bytes, signer_id: Optional[str] = None) -> bool:
        # Deterministic placeholder: reject all non-empty signatures by default.
        # Replace with real ECDSA/Ed25519/BLS verifier bound to signer registry.
        return False

# ---------------------------------------------------------------------------
# Defensive defaults for module importers
# ---------------------------------------------------------------------------

__all__ = [
    "ProofVerifier",
    "HashAlg",
    "MerkleProof",
    "BatchMerkleProof",
    "Sibling",
    "AnchorReceipt",
    "SignatureVerifier",
    "BlockHeader",
    "SimpleHeader",
    "ProofError",
    "InvalidProofFormat",
    "VerificationFailed",
    "HashAlgorithmError",
]
